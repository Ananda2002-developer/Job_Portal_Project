from flask import Flask, request, jsonify, send_file
import mysql.connector
from mysql.connector import Error, IntegrityError, Binary
import random, smtplib, io, os, datetime, jwt
from email.mime.text import MIMEText
from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException
from functools import wraps
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)


# ---------------- CONFIG ----------------
db_config = {
"host": os.getenv("HOST"),
"user": os.getenv("USER"),
"password": os.getenv("PASSWORD"),
"database": os.getenv("DATABASE")
}

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")

ADMIN_ID, ADMIN_PASSWORD = os.getenv("ADMIN_ID"), os.getenv("ADMIN_PASSWORD")

OTP_EXPIRY_MINUTES = int(os.getenv("OTP_EXPIRY_MINUTES", 10))
SESSION_EXPIRY_HOURS = int(os.getenv("SESSION_EXPIRY_HOURS", 2))

# Twilio / Email
TWILIO_SID, TWILIO_AUTH_TOKEN = os.getenv("TWILIO_SID"), os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_PHONE = os.getenv("TWILIO_PHONE")
SMTP_SERVER, SMTP_PORT = os.getenv("SMTP_SERVER"), int(os.getenv("SMTP_PORT"))
EMAIL_ADDRESS, EMAIL_PASSWORD = os.getenv("EMAIL_ADDRESS"), os.getenv("EMAIL_PASSWORD")


# ---------------- HELPERS ----------------
def send_sms(phone_number, message):
    client = Client(TWILIO_SID, TWILIO_AUTH_TOKEN)
    message = client.messages.create(
        body=message,
        from_=TWILIO_PHONE,
        to=phone_number
    )

def send_email(to_email, subject, message):
    msg = MIMEText(message)
    msg["Subject"] = subject
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = to_email
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.send_message(msg)

def validate_json(required_fields):
    if not request.is_json:
        return None, (jsonify({"error": "Invalid JSON format!"}), 400)
    data = request.get_json(silent=True)
    if data is None:
        return None, (jsonify({"error": "Malformed JSON!"}), 400)
    for f in required_fields:
        if f not in data:
            return None, (jsonify({"error": f"Missing required field: {f}!"}), 400)
    return data, None

def generate_otp():
    return str(random.randint(100000, 999999))

def get_server_connection():
    return mysql.connector.connect(
        host=db_config["host"],
        user=db_config["user"],
        password=db_config["password"]
    )

def get_db_connection():
    return mysql.connector.connect(**db_config)

def init_db():
    conn = get_server_connection()
    cursor = conn.cursor()
    cursor.execute(f"CREATE DATABASE IF NOT EXISTS {db_config['database']}")
    cursor.close()
    conn.close()
    conn = get_db_connection()
    cursor = conn.cursor()
    with open("schema.sql", "r") as f:
        schema_sql = f.read()
    for statement in schema_sql.split(";"):
        stmt = statement.strip()
        if stmt:
            cursor.execute(stmt)
    conn.commit()
    cursor.close()
    conn.close()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            try:
                token = request.headers["Authorization"].split(" ")[1]
            except:
                return jsonify({"error": "Invalid token header!"}), 401
        if not token:
            return jsonify({"error": "Token is missing!"}), 401
        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            current_user = data["user"]
            role = data["role"]
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Access denied!"}), 401
        except Exception:
            return jsonify({"error": "Access denied!"}), 401
        return f(current_user, role, *args, **kwargs)
    return decorated


# ---------------- ROUTES ----------------
@app.route('/register_jobseeker_unverified', methods=['POST'])
def register_jobseeker_unverified():
    data, error = validate_json(["phone_number", "name", "email", "dob", "highest_degree", "specialization", "work_experience"])
    if error: return error
    phone_otp = generate_otp()
    email_otp = generate_otp()
    expiry_time = datetime.datetime.now() + datetime.timedelta(minutes=OTP_EXPIRY_MINUTES)
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            DELETE FROM JOBSEEKERS 
            WHERE IS_VERIFIED = 0 AND (PHONE_NUMBER = %s OR EMAIL = %s)
        """, (data["phone_number"], data["email"]))
        cursor.execute("""
            SELECT IS_VERIFIED FROM JOBSEEKERS 
            WHERE PHONE_NUMBER = %s AND EMAIL = %s
        """, (data["phone_number"], data["email"]))
        result = cursor.fetchone()
        if result and result[0] == 1:
            return jsonify({"error": "Jobseeker already exists!"}), 400
        cursor.execute("""
            INSERT INTO JOBSEEKERS 
            (PHONE_NUMBER, NAME, EMAIL, DOB, HIGHEST_DEGREE, SPECIALIZATION, WORK_EXPERIENCE, PHONE_OTP, PHONE_OTP_EXPIRY, EMAIL_OTP, EMAIL_OTP_EXPIRY, IS_VERIFIED) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (data["phone_number"], data["name"], data["email"], data["dob"], data["highest_degree"], data["specialization"], data["work_experience"], phone_otp, expiry_time, email_otp, expiry_time, 0))
        send_sms("+91" + data["phone_number"], "The OTP to verify your phone number for your registration in JOB PORTAL SYSTEM is " + phone_otp + ".")
        send_email(data["email"], "VERIFY YOUR REGISTRATION IN JOB PORTAL SYSTEM", "The OTP to verify your email id for your registration in JOB PORTAL SYSTEM is " + email_otp + ".")
        conn.commit()
        return jsonify({"message": f"OTPs sent successfully. They are valid for {OTP_EXPIRY_MINUTES} minutes!"}), 200
    except IntegrityError:
        if 'conn' in locals() and conn:
            conn.rollback()
        return jsonify({"error": "Phone number or email already exists!"}), 409
    except (smtplib.SMTPException, TwilioRestException) as e:
        if 'conn' in locals() and conn:
            conn.rollback()
        return jsonify({"error": f"SMS/Email service error: {str(e)}"}), 502
    except Error as e:
        if 'conn' in locals() and conn:
            conn.rollback()
        return jsonify({"error": f"Database/server error: {str(e)}"}), 500
    except Exception as e:
        if 'conn' in locals() and conn:
            conn.rollback()
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()
        if 'conn' in locals() and conn:
            conn.close()

@app.route('/register_employer_unverified', methods=['POST'])
def register_employer_unverified():
    data, error = validate_json(["phone_number", "name", "email", "company_name"])
    if error: return error
    phone_otp = generate_otp()
    email_otp = generate_otp()
    expiry_time = datetime.datetime.now() + datetime.timedelta(minutes=OTP_EXPIRY_MINUTES)
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            DELETE FROM EMPLOYERS 
            WHERE IS_VERIFIED = 0 AND (PHONE_NUMBER = %s OR EMAIL = %s)
        """, (data["phone_number"], data["email"]))
        cursor.execute("""
            SELECT IS_VERIFIED FROM EMPLOYERS 
            WHERE PHONE_NUMBER = %s AND EMAIL = %s
        """, (data["phone_number"], data["email"]))
        result = cursor.fetchone()
        if result and result[0] == 1:
            return jsonify({"error": "Employer already exists!"}), 400
        cursor.execute("""
            INSERT INTO EMPLOYERS 
            (PHONE_NUMBER, NAME, EMAIL, COMPANY_NAME, PHONE_OTP, PHONE_OTP_EXPIRY, EMAIL_OTP, EMAIL_OTP_EXPIRY, IS_VERIFIED) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (data["phone_number"], data["name"], data["email"], data["company_name"], phone_otp, expiry_time, email_otp, expiry_time, 0))
        send_sms("+91" + data["phone_number"], "The OTP to verify your phone number for your registration in JOB PORTAL SYSTEM is " + phone_otp + ".")
        send_email(data["email"], "VERIFY YOUR REGISTRATION IN JOB PORTAL SYSTEM", "The OTP to verify your email id for your registration in JOB PORTAL SYSTEM is " + email_otp + ".")
        conn.commit()
        return jsonify({"message": f"OTPs sent successfully. They are valid for {OTP_EXPIRY_MINUTES} minutes!"}), 200
    except IntegrityError:
        if 'conn' in locals() and conn:
            conn.rollback()
        return jsonify({"error": "Phone number or email already exists!"}), 409
    except (smtplib.SMTPException, TwilioRestException) as e:
        if 'conn' in locals() and conn:
            conn.rollback()
        return jsonify({"error": f"SMS/Email service error: {str(e)}"}), 502
    except Error as e:
        if 'conn' in locals() and conn:
            conn.rollback()
        return jsonify({"error": f"Database/server error: {str(e)}"}), 500
    except Exception as e:
        if 'conn' in locals() and conn:
            conn.rollback()
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()
        if 'conn' in locals() and conn:
            conn.close()

@app.route("/register_jobseeker_verified", methods=["PUT"])
def register_jobseeker_verified():
    data, error = validate_json(["phone_number", "email", "phone_otp", "email_otp"])
    if error: return error
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT PHONE_OTP, PHONE_OTP_EXPIRY, EMAIL_OTP, EMAIL_OTP_EXPIRY, IS_VERIFIED FROM JOBSEEKERS 
            WHERE PHONE_NUMBER = %s AND EMAIL = %s
        """, (data["phone_number"], data["email"]))
        result = cursor.fetchone()
        if not result:
            return jsonify({"error": "Jobseeker not found!"}), 404
        stored_phone_otp, phone_expiry, stored_email_otp, email_expiry, is_verified = result
        now = datetime.datetime.now()
        if is_verified == 1:
            return jsonify({"error": "Jobseeker is already verified!"}), 400
        if stored_phone_otp != data["phone_otp"] or now > phone_expiry or stored_email_otp != data["email_otp"] or now > email_expiry:
            return jsonify({"error": "One or both OTPs are invalid or expired!"}), 400
        cursor.execute("""
            UPDATE JOBSEEKERS 
            SET PHONE_OTP = NULL, PHONE_OTP_EXPIRY = NULL, EMAIL_OTP = NULL, EMAIL_OTP_EXPIRY = NULL, IS_VERIFIED= 1 
            WHERE PHONE_NUMBER = %s AND EMAIL = %s
        """, (data["phone_number"], data["email"]))
        conn.commit()
        send_sms("+91" + data["phone_number"], "You have successfully registered in JOB PORTAL SYSTEM.")
        send_email(data["email"], "REGISTRATION SUCCESSFUL", "You have successfully registered in JOB PORTAL SYSTEM.")
        return jsonify({"message": "Registration successful!"}), 200
    except (smtplib.SMTPException, TwilioRestException) as e:
        if 'conn' in locals() and conn:
            conn.rollback()
        return jsonify({"error": f"SMS/Email service error: {str(e)}"}), 502
    except Error as e:
        if 'conn' in locals() and conn:
            conn.rollback()
        return jsonify({"error": f"Database/server error: {str(e)}"}), 500
    except Exception as e:
        if 'conn' in locals() and conn:
            conn.rollback()
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()
        if 'conn' in locals() and conn:
            conn.close()

@app.route("/register_employer_verified", methods=["PUT"])
def register_employer_verified():
    data, error = validate_json(["phone_number", "email", "phone_otp", "email_otp"])
    if error: return error
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT PHONE_OTP, PHONE_OTP_EXPIRY, EMAIL_OTP, EMAIL_OTP_EXPIRY, IS_VERIFIED FROM EMPLOYERS 
            WHERE PHONE_NUMBER = %s AND EMAIL = %s
        """, (data["phone_number"], data["email"]))
        result = cursor.fetchone()
        if not result:
            return jsonify({"error": "Employer not found!"}), 404
        stored_phone_otp, phone_expiry, stored_email_otp, email_expiry, is_verified = result
        now = datetime.datetime.now()
        if is_verified == 1:
            return jsonify({"error": "Employer is already verified!"}), 400
        if stored_phone_otp != data["phone_otp"] or now > phone_expiry or stored_email_otp != data["email_otp"] or now > email_expiry:
            return jsonify({"error": "One or both OTPs are invalid or expired!"}), 400
        cursor.execute("""
            UPDATE EMPLOYERS 
            SET PHONE_OTP = NULL, PHONE_OTP_EXPIRY = NULL, EMAIL_OTP = NULL, EMAIL_OTP_EXPIRY = NULL, IS_VERIFIED= 1 
            WHERE PHONE_NUMBER = %s AND EMAIL = %s
        """, (data["phone_number"], data["email"]))
        conn.commit()
        send_sms("+91" + data["phone_number"], "You have successfully registered in JOB PORTAL SYSTEM.")
        send_email(data["email"], "REGISTRATION SUCCESSFUL", "You have successfully registered in JOB PORTAL SYSTEM.")
        return jsonify({"message": "Registration successful!"}), 200
    except (smtplib.SMTPException, TwilioRestException) as e:
        if 'conn' in locals() and conn:
            conn.rollback()
        return jsonify({"error": f"SMS/Email service error: {str(e)}"}), 502
    except Error as e:
        if 'conn' in locals() and conn:
            conn.rollback()
        return jsonify({"error": f"Database/server error: {str(e)}"}), 500
    except Exception as e:
        if 'conn' in locals() and conn:
            conn.rollback()
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()
        if 'conn' in locals() and conn:
            conn.close()

@app.route('/login_unverified', methods=['PUT'])
def login_unverified():
    data, error = validate_json(["phone_number", "role"])
    if error: return error 
    phone_otp = generate_otp()
    expiry_time = datetime.datetime.now() + datetime.timedelta(minutes=OTP_EXPIRY_MINUTES)
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        if data["role"] == "jobseeker":
            cursor.execute("""
                SELECT IS_VERIFIED FROM JOBSEEKERS 
                WHERE PHONE_NUMBER = %s
            """, (data["phone_number"],))
        elif data["role"] == "employer":
            cursor.execute("""
                SELECT IS_VERIFIED FROM EMPLOYERS 
                WHERE PHONE_NUMBER = %cs
            """, (data["phone_number"],))
        else:
            return jsonify({"error": "Invalid role!"}), 400
        result = cursor.fetchone()
        if not result:
            return jsonify({"error": "User not found!"}), 404
        if result[0] != 1:
            return jsonify({"error": "User not verified yet!"}), 401
        if data["role"] == "jobseeker":
            cursor.execute("""
                UPDATE JOBSEEKERS 
                SET PHONE_OTP = %s, PHONE_OTP_EXPIRY = %s 
                WHERE PHONE_NUMBER = %s
            """, (phone_otp, expiry_time, data["phone_number"]))
        else:
            cursor.execute("""
                UPDATE EMPLOYERS 
                SET PHONE_OTP = %s, PHONE_OTP_EXPIRY = %s 
                WHERE PHONE_NUMBER = %s
            """, (phone_otp, expiry_time, data["phone_number"]))
        send_sms("+91" + data["phone_number"], "The OTP to log into JOB PORTAL SYSTEM is " + phone_otp + ".")
        conn.commit()
        return jsonify({"message": f"OTP sent successfully. It is valid for {OTP_EXPIRY_MINUTES} minutes!"}), 200
    except (smtplib.SMTPException, TwilioRestException) as e:
        if 'conn' in locals() and conn:
            conn.rollback()
        return jsonify({"error": f"SMS/Email service error: {str(e)}"}), 502
    except Error as e:
        if 'conn' in locals() and conn:
            conn.rollback()
        return jsonify({"error": f"Database/server error: {str(e)}"}), 500
    except Exception as e:
        if 'conn' in locals() and conn:
            conn.rollback()
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()
        if 'conn' in locals() and conn:
            conn.close()

@app.route("/login_verified", methods=["PUT"])
def login_verified():
    data, error = validate_json(["phone_number", "phone_otp", "role"])
    if error: return error 
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        if data["role"] == "jobseeker":
            cursor.execute("""
                SELECT PHONE_OTP, PHONE_OTP_EXPIRY, IS_VERIFIED FROM JOBSEEKERS
                WHERE PHONE_NUMBER = %s
            """, (data["phone_number"],))
        elif data["role"] == "employer":
            cursor.execute("""
                SELECT PHONE_OTP, PHONE_OTP_EXPIRY, IS_VERIFIED FROM EMPLOYERS 
                WHERE PHONE_NUMBER = %s
            """, (data["phone_number"],))
        else:
            return jsonify({"error": "Invalid role!"}), 400
        result = cursor.fetchone()
        if not result:
            return jsonify({"error": "User not found!"}), 404
        if not result[0] or not result[1]:
            return jsonify({"error": "Invalid role!"}), 404
        stored_phone_otp, phone_expiry, is_verified = result
        if is_verified != 1:
            return jsonify({"error": "User not verified yet!"}), 401
        if stored_phone_otp != data["phone_otp"] or datetime.datetime.now() > phone_expiry:
            return jsonify({"error": "OTP is either invalid or expired!"}), 401
        token = jwt.encode(
            {
                "user": data["phone_number"],
                "role": data["role"],
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=SESSION_EXPIRY_HOURS)
            },
            app.config["SECRET_KEY"],
            algorithm="HS256"
        )
        if data["role"] == "jobseeker":
            cursor.execute("""
                UPDATE JOBSEEKERS 
                SET PHONE_OTP = NULL, PHONE_OTP_EXPIRY = NULL 
                WHERE PHONE_NUMBER = %s
            """, (data["phone_number"],))
        else:
            cursor.execute("""
                UPDATE EMPLOYERS 
                SET PHONE_OTP = NULL, PHONE_OTP_EXPIRY = NULL 
                WHERE PHONE_NUMBER = %s
            """, (data["phone_number"],))
        conn.commit()
        return jsonify({"message": "Login successful!", "token": token}), 200
    except Error as e:
        if 'conn' in locals() and conn:
            conn.rollback()
        return jsonify({"error": f"Database/server error: {str(e)}"}), 500
    except Exception as e:
        if 'conn' in locals() and conn:
            conn.rollback()
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()
        if 'conn' in locals() and conn:
            conn.close()

@app.route("/post_job", methods=["POST"])
@token_required
def post_jobs(current_user, role):
    data, error = validate_json(["job_title", "specialization", "minimum_work_experience", "location", "salary"])
    if error: return error
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        if role != "employer":
            return jsonify({"error": "Access denied!"}), 401
        cursor.execute("""
            SELECT ID FROM EMPLOYERS 
            WHERE PHONE_NUMBER = %s
        """, (current_user,))
        result = cursor.fetchone()
        if not result:
            return jsonify({"error": "User not found!"}), 404
        cursor.execute("""
            INSERT INTO JOBS 
            (JOB_TITLE, SPECIALIZATION, MINIMUM_WORK_EXPERIENCE, LOCATION, SALARY, EMPLOYER_ID) 
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (data["job_title"], data["specialization"], data["minimum_work_experience"], data["location"], data["salary"], result[0]))
        conn.commit()
        return jsonify({"message": "Job posted successfully!"}), 201
    except IntegrityError:
        if 'conn' in locals() and conn:
            conn.rollback()
        return jsonify({"error": "Duplicate job already exists!"}), 409
    except Error as e:
        if 'conn' in locals() and conn:
            conn.rollback()
        return jsonify({"error": f"Database/server error: {str(e)}"}), 500
    except Exception as e:
        if 'conn' in locals() and conn:
            conn.rollback()
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()
        if 'conn' in locals() and conn:
            conn.close()

@app.route("/view_posted_jobs", methods=["GET"])
@token_required
def view_posted_jobs(current_user, role):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        if role != "employer":
            return jsonify({"error": "Access denied!"}), 401
        cursor.execute("""
            SELECT ID FROM EMPLOYERS WHERE 
            PHONE_NUMBER = %s
        """, (current_user,))
        result = cursor.fetchone()
        if not result:
            return jsonify({"error": "User not found!"}), 404
        cursor.execute("""
            SELECT JOB_TITLE, SPECIALIZATION, MINIMUM_WORK_EXPERIENCE, LOCATION, SALARY, EMPLOYER_ID FROM JOBS 
            WHERE EMPLOYER_ID = %s 
        """, (result[0],))
        result = cursor.fetchall()
        return jsonify({"jobs": result}), 200
    except Error as e:
        return jsonify({"error": f"Database/server error: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()
        if 'conn' in locals() and conn:
            conn.close()

@app.route("/delete_job", methods=["DELETE"])
@token_required
def delete_job(current_user, role):
    data, error = validate_json(["job_id"])
    if error: return error
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        if role != "employer":
            return jsonify({"error": "Access denied!"}), 401
        cursor.execute("""
            SELECT ID FROM EMPLOYERS 
            WHERE PHONE_NUMBER = %s
        """, (current_user,))
        result = cursor.fetchone()
        if not result:
            return jsonify({"error": "User not found!"}), 404
        employer_id = result[0]
        cursor.execute("""
            SELECT EMPLOYER_ID FROM JOBS 
            WHERE ID = %s 
        """, (data["job_id"],))
        result = cursor.fetchone()
        if not result:
            return jsonify({"error": "Job not found!"}), 404
        if result[0] != employer_id:
            return jsonify({"error": "Access denied!"}), 401
        cursor.execute("""
            DELETE FROM JOBS 
            WHERE ID = %s 
        """, (data["job_id"],))
        conn.commit()
        return jsonify({"message": "Job post deleted successfully!"}), 200
    except Error as e:
        if 'conn' in locals() and conn:
            conn.rollback()
        return jsonify({"error": f"Database/server error: {str(e)}"}), 500
    except Exception as e:
        if 'conn' in locals() and conn:
            conn.rollback()
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()
        if 'conn' in locals() and conn:
            conn.close()

@app.route("/view_job_applications", methods=["POST"])
@token_required
def view_job_applications(current_user, role):
    data, error = validate_json(["job_id"])
    if error: return error
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        if role != "employer":
            return jsonify({"error": "Access denied!"}), 401
        cursor.execute("""
            SELECT ID FROM EMPLOYERS 
            WHERE PHONE_NUMBER = %s
        """, (current_user,))
        result = cursor.fetchone()
        if not result:
            return jsonify({"error": "User not found!"}), 404
        id = result[0]
        cursor.execute("""
            SELECT EMPLOYER_ID FROM JOBS 
            WHERE ID = %s
        """, (data["job_id"],))
        result = cursor.fetchone()
        if not result:
            return jsonify({"error": "Job not found!"}), 404
        if id != result[0]:
            return jsonify({"error": "Acccess denied!"}), 401
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT JA.ID, JS.PHONE_NUMBER, JS.NAME, JS.EMAIL, DATE_FORMAT(JS.DOB, '%Y-%m-%d') AS DOB, JS.HIGHEST_DEGREE, JS.SPECIALIZATION, JS.WORK_EXPERIENCE 
            FROM JOBSEEKERS JS INNER JOIN JOB_APPLICATIONS JA 
            ON JS.ID = JA.JOBSEEKER_ID 
            WHERE JA.JOB_ID = %s 
        """, (data["job_id"],))
        result = cursor.fetchall()
        conn.commit()
        return jsonify({"applications": result}), 200
    except Error as e:
        if 'conn' in locals() and conn:
            conn.rollback()
        return jsonify({"error": f"Database/server error: {str(e)}"}), 500
    except Exception as e:
        if 'conn' in locals() and conn:
            conn.rollback()
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()
        if 'conn' in locals() and conn:
            conn.close()

@app.route("/view_resume", methods=["POST"])
@token_required
def view_resume(current_user, role):
    data, error = validate_json(["job_application_id"])
    if error: return error
    try:
        conn = get_db_connection()
        cursor = conn.cursor(buffered=True)
        if role != "employer":
            return jsonify({"error": "Access denied!"}), 401
        cursor.execute("""
            SELECT ID FROM EMPLOYERS 
            WHERE PHONE_NUMBER = %s
        """, (current_user,))
        result = cursor.fetchone()
        if not result:
            return jsonify({"error": "User not found!"}), 404
        employer_id = result[0]
        cursor.execute("""
            SELECT JOB_ID FROM JOB_APPLICATIONS 
            WHERE ID = %s
        """, (data["job_application_id"],))
        result = cursor.fetchone()
        if not result:
            return jsonify({"error": "Job not found!"}), 404
        job_id = result[0]
        cursor.execute("""
            SELECT ID FROM JOBS 
            WHERE EMPLOYER_ID = %s
        """, (employer_id,))
        result = cursor.fetchone()
        if not result:
            return jsonify({"error": "Job not found!"}), 404
        if result[0] != job_id:
            return jsonify({"error": "Access denied!"}), 401
        cursor.execute("""
            SELECT RESUME_NAME, RESUME_DATA FROM JOB_APPLICATIONS 
            WHERE ID = %s
        """, (data["job_application_id"],))
        result = cursor.fetchone()
        if not result:
            return jsonify({"error": "Job not found!"}), 404
        filename, filedata = result
        return send_file(
            io.BytesIO(filedata),
            download_name=filename,
            as_attachment=True,
            mimetype="application/pdf"
        ), 200
    except Error as e:
        return jsonify({"error": f"Database/server error: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()
        if 'conn' in locals() and conn:
            conn.close()

@app.route("/view_active_jobs", methods=["GET"])
@token_required
def view_active_jobs(current_user, role):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        if role != "jobseeker":
            return jsonify({"error": "Access denied!"}), 401
        cursor.execute("""
            SELECT ID, SPECIALIZATION, WORK_EXPERIENCE FROM JOBSEEKERS 
            WHERE PHONE_NUMBER = %s
        """, (current_user,))
        result = cursor.fetchone()
        if not result:
            return jsonify({"error": "User not found!"}), 404
        id, specialization, work_experience = result
        cursor.execute("""
            SELECT E.COMPANY_NAME, J.ID, J.JOB_TITLE, J.SPECIALIZATION, J.MINIMUM_WORK_EXPERIENCE, J.LOCATION, J.SALARY
            FROM EMPLOYERS E INNER JOIN JOBS J 
            ON E.ID = J.EMPLOYER_ID 
            WHERE UPPER(J.SPECIALIZATION) = %s 
            AND J.MINIMUM_WORK_EXPERIENCE <= %s 
            AND J.ID NOT IN (
                SELECT JOB_ID FROM JOB_APPLICATIONS 
                WHERE JOBSEEKER_ID = %s
            )
        """, (specialization.upper(), work_experience, id))
        result = cursor.fetchall()
        return jsonify({"jobs": result}), 200
    except Error:
        return jsonify({"error": "Database error!"}), 500
    except Exception:
        return jsonify({"error": "Invalid request!"}), 400
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

@app.route("/job_apply", methods=["POST"])
@token_required
def job_apply(current_user, role):
    if "resume" not in request.files:
        return jsonify({"error": "Resume file is required!"}), 400
    if "job_id" not in request.form:
        return jsonify({"error": "Job id is required!"}), 400
    resume = request.files["resume"]
    job_id = request.form.get("job_id")
    if resume.filename == "":
        return jsonify({"error": "No file selected"}), 404
    if not resume.filename.lower().endswith(".pdf"):
        return jsonify({"error": "Only PDF files are allowed"}), 400 
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        if role != "jobseeker":
            return jsonify({"error": "Access denied!"}), 401
        cursor.execute("""
            SELECT ID, WORK_EXPERIENCE, SPECIALIZATION FROM JOBSEEKERS 
            WHERE PHONE_NUMBER = %s
        """, (current_user,))
        result = cursor.fetchone()
        if not result:
            return jsonify({"error": "User not found!"}), 404
        id, work_experience, specialization = result
        cursor.execute("""
            SELECT MINIMUM_WORK_EXPERIENCE, SPECIALIZATION FROM JOBS 
            WHERE ID = %s
        """, (job_id,))
        result = cursor.fetchone()
        if not result:
            return jsonify({"error": "Job not found!"}), 404
        if result[0] > work_experience or result[1].upper() != specialization.upper():
            return jsonify({"error": "You cannot apply for this job position!"}), 404
        cursor.execute("""
            INSERT INTO JOB_APPLICATIONS
            (RESUME_NAME, RESUME_DATA, JOB_ID, JOBSEEKER_ID) 
            VALUES (%s, %s, %s, %s)
        """, (resume.filename, Binary(resume.read()), job_id, id))
        conn.commit()
        return jsonify({"message": "Job application successful!"}), 201
    except IntegrityError:
        if 'conn' in locals() and conn:
            conn.rollback()
        return jsonify({"error": "You have already applied for this job position!"}), 400
    except Error as e:
        if 'conn' in locals() and conn:
            conn.rollback()
        return jsonify({"error": f"Database/server error: {str(e)}"}), 500
    except Exception as e:
        if 'conn' in locals() and conn:
            conn.rollback()
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()
        if 'conn' in locals() and conn:
            conn.close()

@app.route('/admin_login', methods=['POST'])
def admin_login():
    data, error = validate_json(["id", "password"])
    if error: return error 
    if(data["id"] != ADMIN_ID or data["password"] != ADMIN_PASSWORD):
        return jsonify({"error": "Invalid id or/and password!"}), 401
    try:
        token = jwt.encode(
            {
                "user": data["id"],
                "role": "admin",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=SESSION_EXPIRY_HOURS)
            },
            app.config["SECRET_KEY"],
            algorithm="HS256"
        )
        return jsonify({"message": "Login successful!", "token": token}), 200
    except Error as e:
        return jsonify({"error": f"Database/server error: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500

@app.route("/view_users", methods=["GET"])
@token_required
def view_users(current_user, role):
    data, error = validate_json(["user_type"])
    if error: return error
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        if role != "admin":
            return jsonify({"error": "Access denied!"}), 401
        if data["user_type"] == "jobseeker":
            cursor.execute("""
                SELECT ID, PHONE_NUMBER, NAME, EMAIL, DOB, HIGHEST_DEGREE, SPECIALIZATION, WORK_EXPERIENCE FROM JOBSEEKERS
            """,)
        elif data["user_type"] == "employer":
            cursor.execute("""SELECT ID, PHONE_NUMBER, NAME, EMAIL, COMPANY_NAME FROM EMPLOYERS
            """,)
        else:
            return jsonify({"error": "Invalid user type!"}), 400
        result = cursor.fetchall()
        return jsonify({"users": result}), 200
    except Error as e:
        return jsonify({"error": f"Database/server error: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()
        if 'conn' in locals() and conn:
            conn.close()

@app.route("/delete_user", methods=["DELETE"])
@token_required
def delete_user(current_user, role):
    data, error = validate_json(["user_id", "user_type"])
    if error: return error
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        if role != "admin":
            return jsonify({"error": "Access denied!"}), 401
        if data["user_type"] == "jobseeker":
            cursor.execute("""
                SELECT ID FROM JOBSEEKERS 
                WHERE ID = %s
            """, (data["user_id"],))
            result = cursor.fetchone()
            if not result:
                return jsonify({"error": "User not found!"}), 404
            cursor.execute("""
                DELETE FROM JOBSEEKERS 
                WHERE ID = %s 
            """, (data["user_id"],))
        elif data["user_type"] == "employer":
            cursor.execute("""
                SELECT ID FROM EMPLOYERS 
                WHERE ID = %s
            """, (data["user_id"],))
            result = cursor.fetchone()
            if not result:
                return jsonify({"error": "User not found!"}), 404
            cursor.execute("""
                DELETE FROM EMPLOYERS 
                WHERE ID = %s 
            """, (data["user_id"],))
        else:
            return jsonify({"error": "Invalid user type!"}), 400
        conn.commit()
        return jsonify({"message": "User deleted successfully!"}), 200
    except Error as e:
        if 'conn' in locals() and conn:
            conn.rollback()
        return jsonify({"error": f"Database/server error: {str(e)}"}), 500
    except Exception as e:
        if 'conn' in locals() and conn:
            conn.rollback()
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()
        if 'conn' in locals() and conn:
            conn.close()
        

# ---------------- MAIN FUNCTION ----------------
if __name__ == '__main__':
    init_db()
    print("Database initiated successfully.")
    app.run(debug=True)