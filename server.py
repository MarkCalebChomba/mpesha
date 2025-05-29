from flask import Flask, request, jsonify, g
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
import base64
import requests
import os
import logging
from datetime import datetime
from dotenv import load_dotenv

# Setup
load_dotenv()
app = Flask(__name__)
CORS(app)

# Enhanced configurations
app.config.update(
    SQLALCHEMY_DATABASE_URI='sqlite:///mpesa_transactions.db',
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SQLALCHEMY_POOL_SIZE=20,
    SQLALCHEMY_MAX_OVERFLOW=5,
    SQLALCHEMY_POOL_TIMEOUT=30,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    PERMANENT_SESSION_LIFETIME=1800
)

# Add SQLAlchemy configuration
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mpesa_transactions.db'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Configure rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["500 per minute"],
    storage_uri="memory://"
)

# Custom key function for phone number rate limiting
def get_phone_number():
    if request.method == "POST" and request.is_json:
        return str(request.json.get('phone', ''))
    return ''

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Enhanced Transaction Model
class Transaction(db.Model):
    __tablename__ = 'transactions'
    
    id = db.Column(db.Integer, primary_key=True)
    phone_number = db.Column(db.String(20), nullable=False, index=True)
    amount = db.Column(db.Float, nullable=False)
    transaction_type = db.Column(db.String(20), nullable=False, index=True)
    transaction_id = db.Column(db.String(100), unique=True, index=True)
    status = db.Column(db.String(20), default='pending', index=True)
    result_desc = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'phone_number': self.phone_number,
            'amount': self.amount,
            'transaction_type': self.transaction_type,
            'transaction_id': self.transaction_id,
            'status': self.status,
            'result_desc': self.result_desc,
            'created_at': self.created_at.isoformat()
        }
    
    @staticmethod
    def get_filtered_transactions(
        phone_number=None, 
        status=None, 
        transaction_type=None, 
        start_date=None, 
        end_date=None,
        page=1,
        per_page=10
    ):
        try:
            query = Transaction.query
            
            if phone_number:
                query = query.filter_by(phone_number=phone_number)
            if status:
                query = query.filter_by(status=status)
            if transaction_type:
                query = query.filter_by(transaction_type=transaction_type)
            if start_date:
                query = query.filter(Transaction.created_at >= start_date)
            if end_date:
                query = query.filter(Transaction.created_at <= end_date)
                
            return query.order_by(Transaction.created_at.desc()).paginate(
                page=page, per_page=per_page, error_out=False
            )
        except Exception as e:
            logger.error(f"Database query error: {str(e)}")
            return None

# Create database tables
with app.app_context():
    db.create_all()

# Request validation middleware
@app.before_request
def before_request():
    g.start_time = datetime.utcnow()
    
    if request.method == 'POST' and not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415

@app.after_request
def after_request(response):
    if hasattr(g, 'start_time'):
        elapsed = datetime.utcnow() - g.start_time
        logger.info(f"Request processed in {elapsed.total_seconds():.3f} seconds")
    
    db.session.remove()
    return response

# Enhanced error handling
@app.errorhandler(Exception)
def handle_error(error):
    logger.error(f"Unhandled error: {str(error)}", exc_info=True)
    return jsonify({
        "error": "Internal server error",
        "message": str(error) if app.debug else "An unexpected error occurred"
    }), 500

# Utility functions
def generate_access_token():
    try:
        consumer_key = os.getenv('MPESA_CONSUMER_KEY')
        consumer_secret = os.getenv('MPESA_CONSUMER_SECRET')
        auth = base64.b64encode(f"{consumer_key}:{consumer_secret}".encode()).decode()
        
        headers = {
            'Authorization': f'Basic {auth}'
        }
        
        url = "https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json()['access_token']
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error generating access token: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Error generating access token: {str(e)}")
        raise

def generate_password():
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    shortcode = os.getenv('MPESA_SHORTCODE')
    passkey = os.getenv('MPESA_PASSKEY')
    
    password_str = f"{shortcode}{passkey}{timestamp}"
    password = base64.b64encode(password_str.encode()).decode()
    
    return {
        'password': password,
        'timestamp': timestamp
    }

def generate_security_credential():
    """Generate security credential for B2C using production certificate"""
    try:
        cert_path = os.path.join(os.path.dirname(__file__), 'ProductionCertificate.cer')
        with open(cert_path, 'rb') as cert_file:
            cert_data = cert_file.read()
            security_credential = base64.b64encode(cert_data).decode('utf-8')
            return security_credential
    except Exception as e:
        logger.error(f"Error generating security credential: {str(e)}")
        return os.getenv('SECURITY_CREDENTIAL')  # Fallback to env variable

# Routes
@app.route('/stk_push', methods=['POST'])
@limiter.limit("3 per minute", key_func=get_phone_number)
def stk_push():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON"}), 400

        required_fields = ['phone', 'amount']
        if not all(field in data for field in required_fields):
            return jsonify({"error": "Missing required fields", "required": required_fields}), 400

        amount = data['amount']
        phone = data['phone']

        logger.info(f"Processing STK push for phone: {phone}, amount: {amount}")

        access_token = generate_access_token()
        password_data = generate_password()

        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }

        # Use the new /stk_callback endpoint as the callback URL
        callback_url = os.getenv('CALLBACK_URL') or 'http://your-server-domain/stk_callback'

        payload = {
            "BusinessShortCode": os.getenv('MPESA_SHORTCODE'),
            "Password": password_data['password'],
            "Timestamp": password_data['timestamp'],
            "TransactionType": "CustomerPayBillOnline",
            "Amount": amount,
            "PartyA": phone,
            "PartyB": os.getenv('MPESA_SHORTCODE'),
            "PhoneNumber": phone,
            "CallBackURL": callback_url,
            "AccountReference": f"Test_{phone}",
            "TransactionDesc": f"Payment_{datetime.now().strftime('%Y%m%d%H%M%S')}" 
        }
        
        response = requests.post(
            'https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest',
            json=payload,
            headers=headers
        )
        
        logger.info(f"STK push response: {response.text}")
        
        if response.status_code == 200:
            # Save transaction
            transaction = Transaction(
                phone_number=phone,
                amount=float(amount),
                transaction_type='stk_push',
                transaction_id=response.json().get('CheckoutRequestID'),
                status='pending'
            )
            db.session.add(transaction)
            db.session.commit()
        
        return jsonify(response.json())
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error processing STK push: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/query_status', methods=['POST'])
def query_status():
    try:
        data = request.json
        if not data or 'CheckoutRequestID' not in data:
            return jsonify({"error": "Missing CheckoutRequestID"}), 400
            
        checkout_request_id = data['CheckoutRequestID']
        
        # First check local transaction status
        transaction = Transaction.query.filter_by(transaction_id=checkout_request_id).first()
        if transaction and transaction.status in ['completed', 'failed']:
            return jsonify({
                "ResultCode": "0" if transaction.status == "completed" else "1",
                "ResultDesc": transaction.result_desc or transaction.status,
                "CheckoutRequestID": checkout_request_id,
                "from_cache": True
            })
        
        # If not found or still pending, query M-PESA
        access_token = generate_access_token()
        password_data = generate_password()
        
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        
        payload = {
            "BusinessShortCode": os.getenv('MPESA_SHORTCODE'),
            "Password": password_data['password'],
            "Timestamp": password_data['timestamp'],
            "CheckoutRequestID": checkout_request_id
        }
        
        response = requests.post(
            'https://api.safaricom.co.ke/mpesa/stkpushquery/v1/query',
            json=payload,
            headers=headers
        )
        
        response_data = response.json()
        logger.info(f"Status query response: {response.text}")
          # Update transaction status if we get a definitive response
        if transaction and 'ResultCode' in response_data:
            result_code = str(response_data.get('ResultCode', ''))
            result_desc = response_data.get('ResultDesc', '')
            
            # Check for callback metadata
            callback_metadata = response_data.get('CallbackMetadata', {}).get('Item', [])
            mpesa_receipt = next((item.get('Value') for item in callback_metadata if item.get('Name') == 'MpesaReceiptNumber'), None)
            transaction_date = next((item.get('Value') for item in callback_metadata if item.get('Name') == 'TransactionDate'), None)
            
            if result_code == '0':
                transaction.status = 'completed'
                if mpesa_receipt:
                    transaction.result_desc = f"Payment completed. Receipt: {mpesa_receipt}"
            elif result_code != '':  # Any non-empty result code other than 0 is considered failed
                transaction.status = 'failed'
                transaction.result_desc = result_desc or "Payment failed"
            
            db.session.commit()
            logger.info(f"Updated transaction {checkout_request_id} status to {transaction.status}")
            
            # Include transaction details in response
            response_data.update({
                'transaction_status': transaction.status,
                'transaction_desc': transaction.result_desc,
                'from_db': True
            })
        
        return jsonify(response_data)
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error querying status: {str(e)}")
        return jsonify({"error": "Network error", "details": str(e)}), 503
    except Exception as e:
        logger.error(f"Error querying status: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/b2c', methods=['POST'])
@limiter.limit("3 per minute", key_func=get_phone_number)
def b2c_payment():
    try:
        data = request.json
        if not data or 'phone' not in data or 'amount' not in data:
            return jsonify({"error": "Missing phone or amount"}), 400

        access_token = generate_access_token()
        if not access_token:
            return jsonify({"error": "Failed to generate access token"}), 500
        
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        
        payload = {
            "InitiatorName": os.getenv('INITIATOR_NAME'),
            "SecurityCredential": generate_security_credential(),
            "CommandID": "BusinessPayment",
            "Amount": data['amount'],
            "PartyA": os.getenv('MPESA_SHORTCODE'),
            "PartyB": data['phone'],
            "Remarks": data.get('remarks', 'B2C Payment'),
            "QueueTimeOutURL": os.getenv('TIMEOUT_URL'),
            "ResultURL": os.getenv('RESULT_URL'),
            "Occasion": data.get('occasion', 'Business Payment')
        }
        
        # Updated B2C endpoint URL
        response = requests.post(
            'https://api.safaricom.co.ke/mpesa/b2c/v1/paymentrequest',
            json=payload,
            headers=headers
        )
        
        if response.status_code != 200:
            logger.error(f"B2C error: {response.text}")
            return jsonify({"error": "B2C request failed", "details": response.text}), response.status_code
        
        logger.info(f"B2C response: {response.text}")
        
        if response.status_code == 200:
            # Save transaction
            transaction = Transaction(
                phone_number=data['phone'],
                amount=float(data['amount']),
                transaction_type='b2c',
                transaction_id=response.json().get('ConversationID'),
                status='pending'
            )
            db.session.add(transaction)
            db.session.commit()
        
        return jsonify(response.json())
    except Exception as e:
        logger.error(f"Error in B2C payment: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/transaction_status', methods=['POST'])
def transaction_status():
    try:
        data = request.json
        if not data or 'transaction_id' not in data:
            return jsonify({"error": "Missing transaction_id"}), 400

        access_token = generate_access_token()
        
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        
        payload = {
            "Initiator": os.getenv('INITIATOR_NAME'),
            "SecurityCredential": generate_security_credential(),
            "CommandID": "TransactionStatusQuery",
            "TransactionID": data['transaction_id'],
            "PartyA": os.getenv('MPESA_SHORTCODE'),
            "IdentifierType": "4",
            "ResultURL": os.getenv('RESULT_URL'),
            "QueueTimeOutURL": os.getenv('TIMEOUT_URL'),
            "Remarks": "Transaction Status Query",
            "Occasion": "Transaction Status"
        }
        
        response = requests.post(
            'https://api.safaricom.co.ke/mpesa/transactionstatus/v1/query',
            json=payload,
            headers=headers
        )
        
        logger.info(f"Transaction status response: {response.text}")
        return jsonify(response.json())
    except Exception as e:
        logger.error(f"Error in transaction status: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/account_balance', methods=['POST'])
def account_balance():
    try:
        access_token = generate_access_token()
        
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        
        payload = {
            "Initiator": os.getenv('INITIATOR_NAME'),
            "SecurityCredential": generate_security_credential(),
            "CommandID": "AccountBalance",
            "PartyA": os.getenv('MPESA_SHORTCODE'),
            "IdentifierType": "4",
            "ResultURL": os.getenv('RESULT_URL'),
            "QueueTimeOutURL": os.getenv('TIMEOUT_URL'),
            "Remarks": "Account Balance Query"
        }
        
        response = requests.post(
            'https://api.safaricom.co.ke/mpesa/accountbalance/v1/query',
            json=payload,
            headers=headers
        )
        
        logger.info(f"Account balance response: {response.text}")
        return jsonify(response.json())
    except Exception as e:
        logger.error(f"Error in account balance: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/timeout', methods=['POST'])
def timeout():
    try:
        data = request.json
        logger.info(f"Timeout received: {data}")
        return jsonify({"status": "success"})
    except Exception as e:
        logger.error(f"Error processing timeout: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Transaction listing endpoint with optional phone number filter and pagination
@app.route('/transactions', methods=['GET'])
@app.route('/transactions/<phone_number>', methods=['GET'])
def get_transactions(phone_number=None):
    try:
        # Get query parameters
        status = request.args.get('status')
        transaction_type = request.args.get('type')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 10)), 100)  # Limit max results
        
        # If phone number is provided in URL, override query parameter
        phone = phone_number or request.args.get('phone')
        
        # Convert date strings to datetime if provided
        if start_date:
            start_date = datetime.strptime(start_date, '%Y-%m-%d')
        if end_date:
            end_date = datetime.strptime(end_date, '%Y-%m-%d')
        
        # Get paginated results
        pagination = Transaction.get_filtered_transactions(
            phone_number=phone,
            status=status,
            transaction_type=transaction_type,
            start_date=start_date,
            end_date=end_date,
            page=page,
            per_page=per_page
        )
        
        if not pagination:
            return jsonify({"error": "Error fetching transactions"}), 500
            
        transactions = [t.to_dict() for t in pagination.items]
        
        return jsonify({
            "transactions": transactions,
            "page": pagination.page,
            "per_page": pagination.per_page,
            "total": pagination.total,
            "pages": pagination.pages
        })
        
    except ValueError as e:
        return jsonify({"error": "Invalid parameter", "details": str(e)}), 400
    except Exception as e:
        logger.error(f"Error fetching transactions: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/transactions/stats', methods=['GET'])
def transaction_stats():
    try:
        # Get total amount transacted
        total_amount = db.session.query(db.func.sum(Transaction.amount)).scalar() or 0
        
        # Get count by status
        status_counts = db.session.query(
            Transaction.status, 
            db.func.count(Transaction.id)
        ).group_by(Transaction.status).all()
        
        # Get count by transaction type
        type_counts = db.session.query(
            Transaction.transaction_type, 
            db.func.count(Transaction.id)
        ).group_by(Transaction.transaction_type).all()
        
        return jsonify({
            'total_amount': float(total_amount),
            'status_counts': dict(status_counts),
            'type_counts': dict(type_counts)
        })
    except Exception as e:
        logger.error(f"Error getting transaction stats: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Update result endpoint to update transaction status
@app.route('/result', methods=['POST'])
def result():
    try:
        data = request.json
        logger.info(f"Result received: {data}")
        
        # Update transaction status based on result
        transaction_id = data.get('CheckoutRequestID') or data.get('ConversationID')
        if transaction_id:
            transaction = Transaction.query.filter_by(transaction_id=transaction_id).first()
            if transaction:
                result_code = str(data.get('ResultCode'))
                transaction.status = 'completed' if result_code == '0' else 'failed'
                transaction.result_desc = data.get('ResultDesc')
                db.session.commit()
                logger.info(f"Updated transaction {transaction_id} status to {transaction.status}")
        
        return jsonify({"status": "success"})
    except Exception as e:
        logger.error(f"Error processing result: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/stk_callback', methods=['POST'])
def stk_callback():
    """Handle M-Pesa STK Push callback"""
    try:
        callback_data = request.get_json()
        logger.info(f"Received STK callback: {callback_data}")
        
        if not callback_data:
            logger.error("Empty callback data received")
            return jsonify({"error": "No callback data received"}), 400
            
        body = callback_data.get('Body', {}).get('stkCallback', {})
        merchant_request_id = body.get('MerchantRequestID')
        checkout_request_id = body.get('CheckoutRequestID')
        result_code = str(body.get('ResultCode', ''))
        result_desc = body.get('ResultDesc', '')
        
        # Extract callback metadata if available
        callback_metadata = body.get('CallbackMetadata', {}).get('Item', [])
        amount = next((item.get('Value') for item in callback_metadata if item.get('Name') == 'Amount'), None)
        mpesa_receipt_number = next((item.get('Value') for item in callback_metadata if item.get('Name') == 'MpesaReceiptNumber'), None)
        transaction_date = next((item.get('Value') for item in callback_metadata if item.get('Name') == 'TransactionDate'), None)
        
        logger.info(f"""
        Detailed callback info:
        - Checkout ID: {checkout_request_id}
        - Result Code: {result_code}
        - Description: {result_desc}
        - Amount: {amount}
        - Receipt: {mpesa_receipt_number}
        - Date: {transaction_date}
        """)
        
        if not checkout_request_id:
            logger.error("Missing CheckoutRequestID in callback")
            return jsonify({"error": "Missing CheckoutRequestID"}), 400
            
        # Update transaction status
        transaction = Transaction.query.filter_by(transaction_id=checkout_request_id).first()
        if transaction:
            if result_code == '0':
                transaction.status = 'completed'
            else:
                transaction.status = 'failed'
            
            transaction.result_desc = result_desc
            db.session.commit()
            logger.info(f"Updated transaction {checkout_request_id} status to {transaction.status} via callback")
            
        return jsonify({"success": True})
        
    except Exception as e:
        logger.error(f"Error processing callback: {str(e)}")
        return jsonify({"error": str(e)}), 500



# Error handler for rate limiting
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        "error": "rate limit exceeded",
        "message": str(e.description)
    }), 429

if __name__ == '__main__':
    # Production configuration for EC2
    logger.info("Starting M-Pesa server on EC2...")
    app.config['SERVER_NAME'] = '3.144.107.16:5000'  # Public IP
    app.config['PREFERRED_URL_SCHEME'] = 'http'
    
    # Configure host to listen on private IP
    app.run(
        host='172.31.9.246',  # Private IP
        port=5000,
        debug=False,
        threaded=True,
        ssl_context=None  # Disable SSL for now - consider using HTTPS in production
    )
