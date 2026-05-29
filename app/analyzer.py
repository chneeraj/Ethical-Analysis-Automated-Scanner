from .config import SQL_ERRORS

def detect_sql_error(response_text):

    return any(
        error in response_text.lower()
        for error in SQL_ERRORS
    )

def detect_sensitive_data(content, keywords):

    return any(
        keyword in content.lower()
        for keyword in keywords
    )