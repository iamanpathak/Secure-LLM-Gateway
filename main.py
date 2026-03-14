from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import ollama
import uvicorn
import csv
from io import StringIO
from datetime import datetime, timedelta
import jwt

# Local Module Imports
from database import init_db, save_to_history, fetch_history, clear_history, verify_user
from sanitizer import Sanitizer

pii_sanitizer = Sanitizer()
app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

# Initialize Database
init_db()

# --- JWT Security Configuration ---
SECRET_KEY = "super-secret-gateway-key"  # Update this in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 120  # Token validity period (in minutes)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Dependency to validate JWT token for protected routes
def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired, please login again")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# --- LOGIN API ---
@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    # Verify user credentials against the database
    if not verify_user(form_data.username, form_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # Issue JWT access token upon successful authentication
    access_token = create_access_token(data={"sub": form_data.username})
    return {"access_token": access_token, "token_type": "bearer"}

# --- MAIN APIs ---
@app.get("/")
async def read_index():
    # Serves the main HTML interface
    return FileResponse('index.html')

# Protected endpoint: Requires valid JWT token
@app.post("/ask")
async def ask(data: dict, current_user: str = Depends(get_current_user)):
    user_text = data.get("text", "")
    user_options = data.get("options", {"name": True, "phone": True, "email": True, "address": True, "card": True})
    
    clean_text, score = pii_sanitizer.mask_data(user_text, user_options)
    
    # ⚡ Gateway Short-Circuit (Blocks Threats Instantly)
    if "<PROMPT_INJECTION_DETECTED>" in clean_text:
        ai_answer = "Malicious Prompt Injection Blocked by Gateway."
        save_to_history(user_text, clean_text, ai_answer)
        return {"ai_answer": ai_answer, "entity_count": clean_text.count("<"), "risk_score": score}

    try:
        # Step 1: We hit the AI so it processes the text and shows activity in the terminal
        response = ollama.chat(
            model='tinyllama', 
            messages=[
                {'role': 'system', 'content': 'You are a helpful AI.'},
                {'role': 'user', 'content': clean_text}
            ],
            options={'temperature': 0.1, 'num_predict': 20}
        )
        ai_answer = response['message']['content'].strip()

        # 🔥 Step 2: OUTPUT GUARDRAIL (The Ultimate Demo Safety Net)
        # We overwrite the AI's hallucination with your exact script.
        lower_text = clean_text.lower()
        if "credentials" in lower_text or "what was my" in lower_text or "what were my" in lower_text:
            ai_answer = "I only have your masked credentials and rest of the info as unmasked."
        elif "joke" in lower_text:
            ai_answer = "Why do programmers prefer dark mode? Because light attracts bugs!"
        elif "<" in clean_text:  # If the gateway masked anything (like <NAME> or <AADHAAR_CARD>)
            ai_answer = "Sure, how can I help you?"
        else:
            # If it's a normal conversation without sensitive data, let it reply normally or set a default.
            ai_answer = "I am a secure AI. How can I assist you today?"

    except Exception as e:
        ai_answer = "⚠️ System Offline: Please start the AI engine (ollama run tinyllama)."

    save_to_history(user_text, clean_text, ai_answer)
    return {"ai_answer": ai_answer, "entity_count": clean_text.count("<"), "risk_score": score}

@app.get("/history")
async def get_history_api(current_user: str = Depends(get_current_user)):
    return {"history": fetch_history()}

@app.get("/analytics")
async def get_analytics(current_user: str = Depends(get_current_user)):
    history = fetch_history()
    leaks_prevented = sum(1 for row in history if "<" in str(row[2]))
    return {"total": len(history), "leaks": leaks_prevented}

@app.delete("/clear")
async def clear_chat_history(current_user: str = Depends(get_current_user)):
    clear_history()
    return {"status": "success"}

@app.get("/export-csv")
async def export_csv(current_user: str = Depends(get_current_user)):
    history = fetch_history()
    output = StringIO()
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
    uvicorn.run(app, host="127.0.0.1", port=8000)