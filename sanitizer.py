import re

class Sanitizer:
    def __init__(self):
        # Comprehensive dictionary of PII and security threat regex patterns
        self.patterns = {
            "EMAIL": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            "PHONE": r'\b(?:\+91[\-\s]?)?[6-9]\d{9}\b',
            "PAN": r'\b[a-zA-Z]{5}[0-9]{4}[a-zA-Z]{1}\b',
            "AADHAAR": r'\b\d{4}\s\d{4}\s\d{4}\b|\b\d{12}\b', 
            "VOTER_ID": r'\b[a-zA-Z]{3}[0-9]{7}\b', 
            "DL": r'\b[a-zA-Z]{2}[0-9]{2}\s?[0-9]{11}\b', 
            "CREDIT_CARD": r'\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{13,16}\b',
            "ADDRESS": r'\b(?:\d{1,5}[a-zA-Z]?\s*[,\-]?\s*)?(?:(?!(?:my|address|is|are|was|were|live|at|in|on|and)\b)[a-zA-Z0-9.,-]+\s+){0,3}(?:Street|St|Road|Rd|Avenue|Ave|Marg|Vihar|Nagar|Enclave|Sector|Phase|Block|Area|City|Village|State|County|Providence|Province|Country)\b(?:\s+(?!(?:my|address|is|are|was|were|live|at|in|on|and)\b)[a-zA-Z0-9.,-]+){0,3}',
            # Dictionary for detecting Prompt Injection and Jailbreak attempts
            "INJECTION": r'(?i)\b(?:ignore all previous instructions|bypass|do anything now|dan|system prompt|jailbreak)\b'
        }

    def mask_data(self, text, options):
        masked_text = text
        detected_count = 0

        # Step 0: Priority check for Prompt Injection vulnerabilities
        injections = re.findall(self.patterns["INJECTION"], masked_text)
        if injections:
            detected_count += len(injections) * 2  
            masked_text = re.sub(self.patterns["INJECTION"], "<PROMPT_INJECTION_DETECTED>", masked_text)

        # Step 1: Sanitize Email Addresses
        if options.get('email'):
            emails = re.findall(self.patterns["EMAIL"], masked_text)
            detected_count += len(emails)
            masked_text = re.sub(self.patterns["EMAIL"], "<EMAIL>", masked_text)

        # Step 2: Sanitize Phone Numbers
        if options.get('phone'):
            phones = re.findall(self.patterns["PHONE"], masked_text)
            detected_count += len(phones)
            masked_text = re.sub(self.patterns["PHONE"], "<PHONE>", masked_text)

        # Step 3: Sanitize Aadhaar (Indian National ID)
        aadhaars = re.findall(self.patterns["AADHAAR"], masked_text)
        if aadhaars:
            detected_count += len(aadhaars)
            masked_text = re.sub(self.patterns["AADHAAR"], "<AADHAAR_CARD>", masked_text)

        # Step 4: Sanitize PAN (Permanent Account Number)
        pans = re.findall(self.patterns["PAN"], masked_text)
        if pans:
            detected_count += len(pans)
            masked_text = re.sub(self.patterns["PAN"], "<PAN_CARD>", masked_text)

        # Step 5: Sanitize Voter ID (EPIC)
        voter_ids = re.findall(self.patterns["VOTER_ID"], masked_text)
        if voter_ids:
            detected_count += len(voter_ids)
            masked_text = re.sub(self.patterns["VOTER_ID"], "<VOTER_ID>", masked_text)

        # Step 6: Sanitize Driving Licenses
        dls = re.findall(self.patterns["DL"], masked_text)
        if dls:
            detected_count += len(dls)
            masked_text = re.sub(self.patterns["DL"], "<DRIVING_LICENSE>", masked_text)

        # Step 7: Sanitize Credit/Debit Card Numbers
        if options.get('card'):
            cards = re.findall(self.patterns["CREDIT_CARD"], masked_text)
            if cards:
                detected_count += len(cards)
                masked_text = re.sub(self.patterns["CREDIT_CARD"], "<CREDIT_CARD>", masked_text)

        # Step 8: Sanitize Physical Addresses 
        if options.get('address'):
            if re.search(self.patterns["ADDRESS"], masked_text, re.IGNORECASE):
                masked_text = re.sub(self.patterns["ADDRESS"], "<ADDRESS>", masked_text, flags=re.IGNORECASE)
                masked_text = re.sub(r'(?:<ADDRESS>[\s,]*)+', '<ADDRESS> ', masked_text).strip()
                detected_count += masked_text.count('<ADDRESS>')

        # Step 9: Sanitize Personal Names (Upgraded Logic)
        if options.get('name'):
            # Rule A: Expanded Conversational Intros (Added 'it was', 'i'm', etc.)
            intro_pattern = re.compile(r'(?i)\b(?:my name is|i am|i\'m|this is|call me|name is|it is|it was|it\'s)\s+([a-zA-Z]+(?:\s[a-zA-Z]+)?)\b')
            for match in intro_pattern.finditer(masked_text):
                name_str = match.group(1)
                if name_str in masked_text:
                    masked_text = masked_text.replace(name_str, "<NAME>")
                    detected_count += 1
                
            # Rule B: Standalone 2-word Capitalized Names anywhere in the sentence
            standalone_pattern = re.compile(r'\b([A-Z][a-z]+\s[A-Z][a-z]+)\b')
            for match in standalone_pattern.findall(masked_text):
                # Ignore basic English sentence starters to avoid false positives
                if match.lower() not in ["it was", "this is", "tell me", "what is"]:
                    masked_text = masked_text.replace(match, "<NAME>")
                    detected_count += 1

        # Calculate overall risk score (Capped at 100%)
        risk_score = min(detected_count * 30, 100)
        
        return masked_text, risk_score