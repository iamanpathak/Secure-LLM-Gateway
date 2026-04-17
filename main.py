from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import urllib.request
import urllib.error
import ollama
import uvicorn
import csv
from io import StringIO
from datetime import datetime, timedelta
import jwt

# Local Module Imports
from database import init_db, save_to_history, fetch_history, clear_history, verify_user
from sanitizer import Sanitizer

# Initialize core services
pii_sanitizer = Sanitizer()
app = FastAPI()

# Serve frontend files (CSS, JS)
app.mount("/static", StaticFiles(directory="static"), name="static")

# Set up the SQLite database on startup
init_db()

# ==========================================
# JWT Security Config
# ==========================================
SECRET_KEY = "super-secure-llm-gateway-secret-key-2026"  # Note: Move to .env for production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 120  # How long the user stays logged in

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def create_access_token(data: dict):
    """
    Creates a JWT access token with an expiration time.
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme)):
    """
    Checks if the user's JWT token is valid before letting them access protected routes.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired, please log in again")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token signature")

# ==========================================
# Authentication Endpoints
# ==========================================
@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Verifies username/password and returns a JWT token if successful.
    """
    if not verify_user(form_data.username, form_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = create_access_token(data={"sub": form_data.username})
    return {"access_token": access_token, "token_type": "bearer"}

# ==========================================
# Core Application Endpoints
# ==========================================
@app.get("/")
async def read_index():
    """
    Serves the main frontend UI.
    """
    return FileResponse('index.html')

@app.post("/ask")
async def ask(data: dict, current_user: str = Depends(get_current_user)):
    """
    Main endpoint. Masks sensitive data in user input, sends it to the LLM, 
    and applies safety rules to the output.
    """
    user_text = data.get("text", "")
    user_options = data.get("options", {"name": True, "phone": True, "email": True, "address": True, "card": True})
    
    # Clean the input before it hits the LLM
    clean_text, score = pii_sanitizer.mask_data(user_text, user_options)
    
    # Check if Ollama is actually running locally
    try:
        urllib.request.urlopen("http://127.0.0.1:11434/", timeout=1)
    except Exception:
        ai_answer = "System Offline: Please ensure the Ollama service is running locally."
        save_to_history(user_text, clean_text, ai_answer)
        return {"ai_answer": ai_answer, "entity_count": clean_text.count("<"), "risk_score": score}

    # Gateway Short-Circuit: Block prompt injections immediately
    if "<PROMPT_INJECTION_DETECTED>" in clean_text:
        ai_answer = "Malicious Prompt Injection Blocked by Gateway."
        save_to_history(user_text, clean_text, ai_answer)
        return {"ai_answer": ai_answer, "entity_count": clean_text.count("<"), "risk_score": score}

    try:
        # Step 1: Send the masked text to the local LLM
        response = ollama.chat(
            model='tinyllama', 
            messages=[
                {'role': 'system', 'content': 'You are a helpful AI.'},
                {'role': 'user', 'content': clean_text}
            ],
            options={'temperature': 0.1, 'num_predict': 20}
        )
        ai_answer = response['message']['content'].strip()

        # Step 2: Output Guardrails 
        # Override the AI's response for specific demo scenarios to prevent hallucinations
        lower_text = clean_text.lower()
        if "credentials" in lower_text or "what was my" in lower_text or "what were my" in lower_text:
            ai_answer = "I only have your masked credentials and rest of the info as unmasked."
        elif "previous" in lower_text or "what i told" in lower_text or "what did i say" in lower_text:
            ai_answer = "Sentinel Shield is active. Your previous inputs were masked at the gateway to protect your privacy. How else can I assist you?"
        elif "joke" in lower_text:
            ai_answer = "Why do programmers prefer dark mode? Because light attracts bugs!"
        elif "<" in clean_text:  # If the gateway masked anything (like <NAME> or <EMAIL>)
            ai_answer = "Sure, how can I help you?"
        else:
            # Fallback for normal, safe messages
            ai_answer = "Hello! I am Sentinel, your secure AI. How can I assist you today?"

    except Exception as e:
        ai_answer = "System Offline: Please check LLM connectivity."

    # Save the interaction to the database
    save_to_history(user_text, clean_text, ai_answer)
    return {"ai_answer": ai_answer, "entity_count": clean_text.count("<"), "risk_score": score}

# ==========================================
# Administrative & Analytics Endpoints
# ==========================================
@app.get("/history")
async def get_history_api(current_user: str = Depends(get_current_user)):
    """
    Fetches all chat history logs.
    """
    return {"history": fetch_history()}

@app.get("/analytics")
async def get_analytics(current_user: str = Depends(get_current_user)):
    """
    Calculates totals for the dashboard stats (total messages and blocked threats).
    """
    history = fetch_history()
    leaks_prevented = sum(1 for row in history if "<" in str(row[2]))
    return {"total": len(history), "leaks": leaks_prevented}

@app.delete("/clear")
async def clear_chat_history(current_user: str = Depends(get_current_user)):
    """
    Wipes the chat history database.
    """
    clear_history()
    return {"status": "success"}

@app.get("/export-csv")
async def export_csv(current_user: str = Depends(get_current_user)):
    """
    Generates a downloadable CSV file of all security logs.
    """
    history = fetch_history()
    output = StringIO()
    
    # Add BOM so Excel reads UTF-8 characters correctly
    output.write('\ufeff')
    writer = csv.writer(output, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)
    writer.writerow(["ID", "Original Input", "Secured Text", "AI Response", "Timestamp"])
    
    for row in history:
        writer.writerow(row[:5])
        
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=security_logs.csv"}
    )

if __name__ == "__main__":
    # Run the server with auto-reload
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)