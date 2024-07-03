from flask import Flask, make_response, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, JWTManager
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError
from flask_sqlalchemy import SQLAlchemy
import logging
from functools import wraps
from sqlalchemy import func
from flask_mail import Mail, Message
import psycopg2
import re
from datetime import datetime, timedelta, date
from sqlalchemy import and_, cast, Date

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:Root@localhost:5432/AtTracker'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'admin'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USERNAME'] = 'kavinnvp55@gmail.com'
app.config['MAIL_PASSWORD'] = 'gybetaximcmkfwdr'
app.config['MAIL_DEBUG'] = True
app.config['SECRET_KEY'] = '521ca85a63664803b13d7300f6beae18'

db = SQLAlchemy(app)
jwt = JWTManager(app)
mail = Mail(app)
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


# creating admin table in attendance database
class Admin(db.Model):
    Admin_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    Email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)


with app.app_context():
    db.create_all()


# user table
class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    Admin_id = db.Column(db.Integer, db.ForeignKey('admin.Admin_id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


with app.app_context():
    db.create_all()


# attendance table
class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    username = db.Column(db.String(50), nullable=False)
    login_time = db.Column(db.DateTime)
    logout_time = db.Column(db.DateTime)
    status = db.Column(db.String(10), nullable=False)


with app.app_context():
    db.create_all()


# leaves table
class Leaves(db.Model):
    LeaveId = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    username = db.Column(db.String(50), nullable=False)
    from_date = db.Column(db.String(50), nullable=False)
    to_date = db.Column(db.String(50), nullable=False)
    reason = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), nullable=False)


with app.app_context():
    db.create_all()


def send_verification_email(user):
    try:
        msg = Message('Welcome to Autointelli!', sender='kavinnvp55@gmail.com', recipients=[user.email])
        msg.body = f"Hello {user.username},\n\nYour account has been created successfully.\n\nUsername: {user.username}\nUseremail: {user.email}\nPassword: {user.password}\n\nThank you!"
        mail.send(msg)
        print("Email sent successfully!")
    except Exception as e:
        print("Error sending email:", e)


def send_leave_email(leaves, user):
    try:
        msg = Message('Leave Application', sender='kavinnvp55@gmail.com', recipients=[user.email])
        msg.body = f"Hello request for leave is submitted successfully ,\n\nYour leave details\n\nfrom_date: {leaves.from_date}\nto_date: {leaves.to_date}\nreason: {leaves.reason}\nstatus: {leaves.status}\n\nThank you!\n{leaves.username}"
        mail.send(msg)
        print("Email sent successfully!")
    except Exception as e:
        print("Error sending email:", e)


def send_leave_approval_email(leaves, user):
    try:
        msg = Message('Leave Application Approval', sender='kavinnvp55@gmail.com', recipients=[user.email])
        msg.body = f"Hello request for leave is Approved successfully ,\n\nYour Leave details.\n\nLeaveId: {leaves.LeaveId}\nuser_id: {leaves.user_id}\nusername: {leaves.username}\nfrom_date: {leaves.from_date}\nto_date: {leaves.to_date}\nreason: {leaves.reason}\nstatus: {leaves.status}\n\nThank you!\n{leaves.username}"
        mail.send(msg)
        print("Email sent successfully!")
    except Exception as e:
        print("Error sending email:", e)


def send_leave_rejection_email(leaves, user):
    try:
        msg = Message('Leave Application Rejection', sender='kavinnvp55@gmail.com', recipients=[user.email])
        msg.body = f"Hello request for leave is Rejected. ,\n\nYour Leave details.\n\nLeaveId: {leaves.LeaveId}\nuser_id: {leaves.user_id}\nusername: {leaves.username}\nfrom_date: {leaves.from_date}\nto_date: {leaves.to_date}\nreason: {leaves.reason}\nstatus: {leaves.status}\n\nThank you!\n{leaves.username}"
        mail.send(msg)
        print("Email sent successfully!")
    except Exception as e:
        print("Error sending email:", e)


# admin login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    try:
        if not data:
            return jsonify({'message': 'Email and password are required'}), 400

        Email = data.get('Email').lower()
        password = data.get('password')
        if not Email or not password:
            return jsonify({'message': 'Email and password are required'}), 400

        admin = Admin.query.filter_by(Email=Email, password=password).first()
        if not admin:
            return jsonify({'message': 'Invalid credentials'}), 401

        # If credentials are valid, create and return JWT token
        access_token = create_access_token(identity=admin.Email)
        return jsonify({"message": "Logged in successfully", "access_token": access_token}), 200
    except Exception as e:
        return jsonify({"message": "Error logging in"}), 500


#  user login and attendance login
@app.route('/userlogin', methods=['POST'])
def userlogin():
    data = request.get_json()
    if not data or 'email' not in data or 'password' not in data:
        return jsonify({"message": "Email and password are required"}), 400
    
    try:
        email = data.get('email').lower()
        password = data.get('password')

        user = User.query.filter_by(email=email, password=password).first()
        if user and user.email == email:
            last_attendance = Attendance.query.filter_by(user_id=user.user_id).order_by(Attendance.id.desc()).first()
            if last_attendance and last_attendance.logout_time:
                status = 'present'
            else:
                status = 'absent'

            new_attendance = Attendance(
                user_id=user.user_id,
                username=user.username,
                login_time=datetime.now().replace(microsecond=0),
                status=status
            )
            db.session.add(new_attendance)
            db.session.commit()
            access_token = create_access_token(identity=user.user_id)
            return jsonify({"message": "Attendance logged in successfully", "access_token": access_token}), 200

        return jsonify({'message': 'Invalid email or password'}), 400

    except Exception as e:
        return jsonify({"message": "Error logging in"}), 500


# add user to user table by admin (use admin login access token)
@app.route('/add_user', methods=['POST'])
@jwt_required()
def add_user():
    try:
        current_admin_email = get_jwt_identity()

        email_regex = r'^\S+@\S+\.\S+$'
        username_regex = r'^[A-Za-z]+$'

        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        if not username:
            return jsonify({'message': 'Username is required'}), 400

        if not re.match(username_regex, username):
            return jsonify({'message': 'Username must contain only alphabetic characters'}), 400

        if not email:
            return jsonify({'message': 'Email is required'}), 400

        if not password:
            return jsonify({'message': 'Password is required'}), 400

        if len(password) < 6:
            return jsonify({'message': 'Your password is weak. Password must be at least 6 characters'}), 400

        admin = Admin.query.filter_by(Email=current_admin_email).first()
        if not admin:
            return jsonify({'message': 'Admin not found'}), 404

        if not re.match(email_regex, email):
            return jsonify({'message': 'Valid email is required'}), 400

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({'message': 'Email already exists'}), 400

        new_user = User(username=username, email=email, password=password, Admin_id=admin.Admin_id,
                        created_at=datetime.now())

        db.session.add(new_user)
        db.session.commit()
        send_verification_email(new_user)

        return jsonify({"message": "User added successfully"}), 201
    except Exception as e:
        return jsonify({"message": f"Error adding user: {str(e)}"}), 400


# update user to user table by admin (use admin login access token)
@app.route('/update_user', methods=['PUT'])
@jwt_required()
def update_user():
    try:
        current_admin_email = get_jwt_identity()

        data = request.get_json()
        user_id = data.get('user_id')
        new_username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        admin = Admin.query.filter_by(Email=current_admin_email).first()
        if not admin:
            return jsonify({'message': 'Admin not found'}), 404

        user = User.query.get(user_id)
        if not user:
            return jsonify({'message': 'User not found'}), 404

        user.username = new_username
        user.email = email
        user.password = password

        leaves = Leaves.query.filter_by(user_id=user_id).all()
        for leave in leaves:
            leave.username = new_username

        db.session.commit()

        attendance = Attendance.query.filter_by(user_id=user_id).all()
        for attendances in attendance:
            attendances.username = new_username

        db.session.commit()

        return jsonify({"message": "User updated successfully"}), 200
    except Exception as e:
        return jsonify({"message": "Error updating user"}), 400


# delete user by admin (use admin login access token)
@app.route('/admin/delete_user/<int:user_id>', methods=['DELETE'])
@jwt_required()
def admin_delete_user(user_id):
    try:
        current_admin_email = get_jwt_identity()

        admin = Admin.query.filter_by(Email=current_admin_email).first()
        if not admin:
            return jsonify({'message': 'Admin not found'}), 404

        user_to_delete = User.query.filter_by(user_id=user_id, Admin_id=admin.Admin_id).first()
        if not user_to_delete:
            return jsonify({'message': 'User not found or does not belong to the admin'}), 404

        related_leaves = Leaves.query.filter_by(user_id=user_id).all()
        for leave in related_leaves:
            db.session.delete(leave)

        related_attendance = Attendance.query.filter_by(user_id=user_id).all()
        for attendance in related_attendance:
            db.session.delete(attendance)

        db.session.delete(user_to_delete)
        db.session.commit()

        return jsonify({'message': 'User and related data deleted successfully'}), 200
    except Exception as e:
        return jsonify({"message": "Error deleting user and related data", "error": str(e)}), 500


# get user by id (use userlogin access token)
@app.route("/getuser/<int:User_id>", methods=["GET"])
@jwt_required()
def getUserById(User_id):
    try:
        user = User.query.get(User_id)
        if user is None:
            return jsonify({"Error": "User not found"}), 404
        user_data = {
            "user_id": user.user_id,
            "username": user.username,
            "password": user.password,
            "email": user.email,
            "Admin_id": user.Admin_id,
            "created_at": str(user.created_at)
        }
        return jsonify(user_data)
    except Exception as e:
        return jsonify({"Error": "Can't able to get user", "Exception": str(e)})


# attendance logout (use attendance login access token)

@app.route('/attendance/logout', methods=['POST'])
@jwt_required()
def logout():
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        if not user:
            return jsonify(message="User not found")

        latest_attendance = Attendance.query.filter_by(user_id=current_user_id).order_by(Attendance.id.desc()).first()

        if latest_attendance:
            latest_attendance.logout_time = datetime.now()
            latest_attendance.status = 'present'
            db.session.commit()
            return jsonify(message="Logout time updated successfully")
        else:
            return jsonify(message="No attendance record found for this user")

    except Exception as e:
        return jsonify(error=str(e))

# get all user from user table (use admin login access token)
@app.route('/get_all_users', methods=['GET'])
@jwt_required()
# @swag_from('GET')
def get_all_users():
    """
     Get All Users
     ---
     parameters:
       - name: Authorization
         in: header
         type: string
         required: true
         description: JWT token obtained during admin login
     responses:
       200:
         description: List of all users
         schema:
           type: object
           properties:
             users:
               type: array
               items:
                 type: object
                 properties:
                   user_id:
                     type: integer
                   username:
                     type: string
                   email:
                     type: string
                   Admin_id:
                     type: integer
                   created_at:
                     type: string
       404:
         description: Admin not found
         schema:
           type: object
           properties:
             message:
               type: string
       500:
         description: Error retrieving users
         schema:
           type: object
           properties:
             message:
               type: string
             error:
               type: string
     """
    try:
        current_admin_email = get_jwt_identity()

        admin = Admin.query.filter_by(Email=str(current_admin_email)).first()

        if not admin:
            return jsonify({'message': 'Admin not found'}), 401

        users = User.query.filter_by(user_id=User.user_id).all()

        users_data = []
        for user in users:
            user_info = {
                'user_id': user.user_id,
                'username': user.username,
                'email': user.email,
                "Admin_id": user.Admin_id,
                "created_at": str(user.created_at)

            }
            users_data.append(user_info)

        return jsonify({'users': users_data}), 200
    except Exception as e:
        return jsonify({"message": "Error retrieving users"}), 500



# apply leave (use userlogin access token)
@app.route('/apply_leave', methods=['POST'])
@jwt_required()
def apply_leave():
    user_id = get_jwt_identity()
    data = request.get_json()
    try:
        from_date = data.get('from_date')
        to_date = data.get('to_date')
        reason = data.get('reason')

        if not from_date or not to_date:
            return jsonify({'message': 'From date and to date are required'}), 400
        try:
            datetime.strptime(from_date, '%Y-%m-%d')
            datetime.strptime(to_date, '%Y-%m-%d')
        except ValueError:
            return jsonify({'message': 'Invalid date format. Please provide dates in YYYY-MM-DD format'}), 400
        if not reason:
            return jsonify({'message': 'Reason is required'}), 400

        if from_date > to_date:
            return jsonify({'message': 'to date cannot be earlier than from date'}), 400

        user = User.query.get(user_id)
        if not user:
            return jsonify({'message': 'User not found'}), 404
        username = user.username

        leave = Leaves(
            user_id=user_id,
            username=username,
            from_date=from_date,
            to_date=to_date,
            reason=reason,
            status='pending'
        )
        db.session.add(leave)
        db.session.commit()
        send_leave_email(leave, user)
        return jsonify({"message": "Leave applied successfully"}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "Error applying leave"}), 401


# get all leave from leave table (use admin login access token)
@app.route('/get_all_leaves', methods=['GET'])
@jwt_required()
# @swag_from('GET')
def get_all_leaves():
    try:
        current_admin_email = get_jwt_identity()

        admin = Admin.query.filter_by(Email=current_admin_email).first()
        if not admin:
            return jsonify({'message': 'Admin not found'}), 404

        leaves = Leaves.query.filter_by(user_id=Leaves.user_id).all()

        leave_data = []
        for leave in leaves:
            leave_info = {
                'LeaveId': leave.LeaveId,
                'user_id': leave.user_id,
                'username': leave.username,
                'from_date': leave.from_date,
                'to_date': leave.to_date,
                'reason': leave.reason,
                'status': leave.status
            }
            leave_data.append(leave_info)

        return jsonify({'leaves': leave_data}), 200
    except Exception as e:
        return jsonify({"message": "Error retrieving leaves"}), 500


# get user leave by id (use userlogin access token)
@app.route('/user_leave/<int:user_id>', methods=['GET'])
@jwt_required()
# @swag_from('GET')
def get_user_leave(user_id):
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'message': 'User not found'}), 404

        user_leave = Leaves.query.filter_by(user_id=user_id).all()
        leave_data = [
            {'LeaveId': leave.LeaveId, 'user_id': leave.user_id, 'username': leave.username, 'reason': leave.reason,
             'status': leave.status} for leave in user_leave]
        return jsonify({'user_leave': leave_data}), 200
    except Exception as e:
        return jsonify({"message": "Error retrieving user leave"}), 500


# get all user attendance (use admin login access token)
@app.route('/attendance/all', methods=['GET'])
@jwt_required()
# @swag_from('GET')
def get_all_attendance():
    try:
        current_admin_email = get_jwt_identity()

        admin = Admin.query.filter_by(Email=current_admin_email).first()
        if not admin:
            return jsonify({'message': 'Admin not found'}), 404

        attendance_records = Attendance.query.join(User).filter(User.user_id == Attendance.user_id).all()

        attendance_data = []
        for record in attendance_records:
            attendance_info = {
                'user_id': record.user_id,
                'username': record.username,
                'login_time': record.login_time.strftime("%Y-%m-%d %H:%M:%S") if record.login_time else None,
                'logout_time': record.logout_time.strftime("%Y-%m-%d %H:%M:%S") if record.logout_time else None
            }
            attendance_data.append(attendance_info)

        return jsonify({'attendance': attendance_data}), 200
    except Exception as e:
        return jsonify({"message": "Error retrieving attendance"}), 500


# get attendance by id (use userlogin access token)
@app.route('/attendance/<int:user_id>', methods=['GET'])
@jwt_required()
def get_attendance_by_user_id(user_id):
    try:
        current_user_id = get_jwt_identity()
        if current_user_id != user_id:
            return jsonify({'message': 'Unauthorized access to attendance data'}), 403

        attendance_data = Attendance.query.filter_by(user_id=user_id).all()

        if not attendance_data:
            return jsonify({'message': 'No attendance data found for this user'}), 404

        attendance_list = []
        for entry in attendance_data:
            attendance_info = {
                'user_id': entry.user_id,
                'username': entry.username,
                'login_time': entry.login_time.strftime("%Y-%m-%d %H:%M:%S"),
                'logout_time': entry.logout_time.strftime("%Y-%m-%d %H:%M:%S") if entry.logout_time else None,
                'status': entry.status
            }
            attendance_list.append(attendance_info)

        return jsonify({'attendance_data': attendance_list}), 200

    except Exception as e:
        print("Error:", e)  # Log the error for debugging
        return jsonify({'message': 'Error fetching attendance data'}), 500

# route for admin to approve leave
@app.route('/approve_leave/<int:leave_id>', methods=['PUT'])
@jwt_required()
# @swag_from('PUT')
def approve_leave(leave_id):
    try:
        current_admin_email = get_jwt_identity()

        admin = Admin.query.filter_by(Email=current_admin_email).first()
        if not admin:
            return jsonify({'message': 'Admin not found'}), 404

        leave = Leaves.query.get(leave_id)
        if not leave:
            return jsonify({'message': 'Leave request not found'}), 404

        leave.status = 'approved'
        db.session.commit()  # Commit changes to the database

        # Update attendance table if leave is approved
        if leave.status == 'approved':
            # Convert from_date and to_date to datetime objects
            from_date = datetime.strptime(leave.from_date, '%Y-%m-%d')
            to_date = datetime.strptime(leave.to_date, '%Y-%m-%d')

            # Find the corresponding attendance records for the leave duration
            leave_duration = to_date - from_date
            for i in range(leave_duration.days + 1):
                date = from_date + timedelta(days=i)
                app.logger.info(f"Checking attendance record for date: {date}")
                # Find the corresponding attendance record for each date
                attendance_record = Attendance.query.filter_by(user_id=leave.user_id, login_time=date.date()).first()
                if attendance_record:
                    app.logger.info(f"Attendance record found for date: {date}")
                    # Update attendance status to indicate leave
                    attendance_record.status = 'leave'
                    db.session.commit()
                else:
                    app.logger.warning(f"No attendance record found for date: {date}")

        user = User.query.get(leave.user_id)
        if not user:
            return jsonify({'message': 'User not found'}), 404

        send_leave_approval_email(leave, user)

        return jsonify({'message': 'Leave request approved successfully'}), 200
    except Exception as e:
        return jsonify({"message": "Error approving leave: {str(e)}"}), 500


@app.route('/reject_leave/<int:leave_id>', methods=['PUT'])
@jwt_required()
# @swag_from('PUT')
def reject_leave(leave_id):
    try:
        current_admin_email = get_jwt_identity()

        admin = Admin.query.filter_by(Email=current_admin_email).first()
        if not admin:
            return jsonify({'message': 'Admin not found'}), 404

        leave = Leaves.query.get(leave_id)
        if not leave:
            return jsonify({'message': 'Leave request not found'}), 404

        leave.status = 'rejected'
        db.session.commit()
        user = User.query.get(leave.user_id)
        if not user:
            return jsonify({'message': 'User not found'}), 404

        send_leave_rejection_email(leave, user)

        return jsonify({'message': 'Leave request rejected successfully'}), 200
    except Exception as e:
        return jsonify({"message": "Error rejecting leave"}), 500

@app.route('/absent_users_data', methods=['GET'])
@jwt_required()
def get_absent_users_data():
    try:
        current_admin_email = get_jwt_identity()

        admin = Admin.query.filter_by(Email=current_admin_email).first()
        if not admin:
            return jsonify({'message': 'Unauthorized: Admin access required'}), 401

        start_date_str = request.args.get('start_date')
        end_date_str = request.args.get('end_date')

        if not start_date_str or not end_date_str:
            return jsonify({'message': 'Both start_date and end_date are required parameters'}), 400

        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d')
        except ValueError:
            return jsonify({'message': 'Invalid date format. Please use YYYY-MM-DD.'}), 400

        absent_users_query = Attendance.query.filter(
            func.date(Attendance.login_time) >= start_date.date(),
            func.date(Attendance.login_time) <= end_date.date(),
            Attendance.status == 'absent'
        )

        absent_users_count = absent_users_query.count()
        absent_users = absent_users_query.all()

        absent_users_data = []
        for user in absent_users:
            user_data = {
                'user_id': user.user_id,
                'username': user.username,
                'login_time': user.login_time.strftime("%Y-%m-%d %H:%M:%S"),
                'logout_time': user.logout_time.strftime("%Y-%m-%d %H:%M:%S") if user.logout_time else None,
                'status': user.status
            }
            absent_users_data.append(user_data)

        return jsonify({'absent_users_count': absent_users_count, 'absent_users': absent_users_data}), 200

    except Exception as e:
        print(e)  # Log the actual error for debugging
        return jsonify({"message": "Error fetching absent users data"}), 400

# Attendance count from date and to date
@app.route('/present_users_data', methods=['GET'])
@jwt_required()
def get_present_users_data():
    try:
        current_admin_email = get_jwt_identity()

        admin = Admin.query.filter_by(Email=current_admin_email).first()
        if not admin:
            return jsonify({'message': 'Error fetching'}), 401

        start_date_str = request.args.get('start_date')
        end_date_str = request.args.get('end_date')

        if not start_date_str or not end_date_str:
            return jsonify({"message": "Start date and end date are required."}), 400

        start_date_str = start_date_str.strip()
        end_date_str = end_date_str.strip()

        start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d')

        present_users_query = Attendance.query.filter(
            func.date(Attendance.login_time) >= start_date.date(),
            func.date(Attendance.login_time) <= end_date.date(),
            Attendance.status == 'present'
        )

        present_users_count = present_users_query.count()

        present_users = present_users_query.all()

        present_users_data = []
        for user in present_users:
            user_data = {
                'user_id': user.user_id,
                'username': user.username,
                'login_time': user.login_time.strftime("%Y-%m-%d %H:%M:%S"),
                'logout_time': user.logout_time.strftime("%Y-%m-%d %H:%M:%S") if user.logout_time else None,
                'status': user.status
            }
            present_users_data.append(user_data)

        return jsonify({'present_users_count': present_users_count, 'present_users': present_users_data}), 200

    except ValueError as ve:
        return jsonify({"message": "Invalid date format. Please use YYYY-MM-DD format.", "error": str(ve)}), 400
    except Exception as e:
        return jsonify({"message": "Admin not found"}), 401

# rejected leave per day count
@app.route('/rejected_leaves/<date>', methods=['GET'])
@jwt_required()
# @swag_from('GET')
def get_rejected_leaves(date):
    try:
        current_admin_email = get_jwt_identity()

        admin = Admin.query.filter_by(Email=current_admin_email).first()
        if not admin:
            return jsonify({'message': 'Admin not found'}), 404

        date_obj = datetime.strptime(date, '%Y-%m-%d')
        formatted_date = date_obj.strftime('%Y-%m-%d')  # Format the date for database query
    except ValueError:
        return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD.'}), 400

    leaves = Leaves.query.filter(
        db.func.lower(Leaves.status) == 'rejected',
        db.func.date(Leaves.from_date) <= formatted_date,
        db.func.date(Leaves.to_date) >= formatted_date
    ).all()

    rejected_leaves = []
    for leave in leaves:
        rejected_leaves.append({
            'LeaveId': leave.LeaveId,
            'user_id': leave.user_id,
            'username': leave.username,
            'from_date': leave.from_date,
            'to_date': leave.to_date,
            'reason': leave.reason,
            'status': leave.status
        })
    leaves_count = len(rejected_leaves)  # Count the rejected leaves retrieved

    return jsonify({'rejected_leaves': rejected_leaves, 'rejected_leave_count': leaves_count})


# Get count of pending leaves for a specific date
@app.route('/pending_leaves/<date>', methods=['GET'])
@jwt_required()
def get_pending_leaves(date):
    try:
        # Get current admin's email from JWT token
        current_admin_email = get_jwt_identity()
        admin = Admin.query.filter_by(Email=current_admin_email).first()
        if not admin:
            logging.error(f'Admin not found for email: {current_admin_email}')
            return jsonify({'message': 'Admin not found'}), 404

        # Convert date string to datetime object
        date_obj = datetime.strptime(date, '%Y-%m-%d')

        # Convert date object to formatted string
        formatted_date = date_obj.strftime('%Y-%m-%d')

        # Filter leaves based on date range and status
        leaves = Leaves.query.filter(
            db.func.lower(Leaves.status) == 'pending',
            Leaves.from_date <= formatted_date,
            Leaves.to_date >= formatted_date
        ).all()

        pending_leaves = []
        for leave in leaves:
            pending_leaves.append({
                'LeaveId': leave.LeaveId,
                'user_id': leave.user_id,
                'username': leave.username,
                'from_date': leave.from_date,
                'to_date': leave.to_date,
                'reason': leave.reason,
                'status': leave.status
            })

        # Count pending leaves
        leaves_count = len(pending_leaves)

        return jsonify({'pending_leaves': pending_leaves, 'pending_leave_count': leaves_count}), 200

    except ValueError:
        logging.error('Invalid date format. Use YYYY-MM-DD.')
        return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD.'}), 400
    except Exception as e:
        logging.error(f'Error fetching pending leaves data: {e}')
        return jsonify({'error': 'Error fetching pending leaves data'}), 500
    # approved leaves data


@app.route('/approved_leaves/<date>', methods=['GET'])
@jwt_required()
def get_approved_leaves(date):
    try:
        current_admin_email = get_jwt_identity()

        admin = Admin.query.filter_by(Email=current_admin_email).first()
        if not admin:
            return jsonify({'message': 'Admin not found'}), 404

        # Convert date string to datetime object
        date_obj = datetime.strptime(date, '%Y-%m-%d')

        # Format the date for database query
        formatted_date = date_obj.strftime('%Y-%m-%d')

        # Retrieve approved leaves for the specified date
        leaves = Leaves.query.filter(
            db.func.lower(Leaves.status) == 'approved',
            Leaves.from_date <= formatted_date,
            Leaves.to_date >= formatted_date
        ).all()

        # Construct response with approved leaves information
        approved_leaves = []
        for leave in leaves:
            approved_leaves.append({
                'LeaveId': leave.LeaveId,
                'user_id': leave.user_id,
                'username': leave.username,
                'from_date': leave.from_date,
                'to_date': leave.to_date,
                'reason': leave.reason,
                'status': leave.status
            })

        # Count approved leaves
        leaves_count = len(approved_leaves)

        return jsonify({'approved_leaves': approved_leaves, 'approved_leave_count': leaves_count})

    except ValueError:
        return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD.'}), 400


# Get  leaves count for a specific date

@app.route('/total_leaves/<date>', methods=['GET'])
@jwt_required()
def get_total_leaves_by_date(date):
    try:
        current_admin_email = get_jwt_identity()

        admin = Admin.query.filter_by(Email=current_admin_email).first()
        if not admin:
            return jsonify({'message': 'Admin not found'}), 404

        date_obj = datetime.strptime(date, '%Y-%m-%d')
    except ValueError:
        return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD.'}), 400

    formatted_date = date_obj.strftime('%Y-%m-%d')

    # Retrieve leaves for the specified date
    leaves = Leaves.query.filter(Leaves.from_date <= formatted_date) \
        .filter(Leaves.to_date >= formatted_date).all()

    # Construct response
    all_leaves = []
    for leave in leaves:
        try:
            # Attempt to remove any newline characters from the reason field
            reason = leave.reason.replace("\n", "")
            leave.status = leave.status.replace("\n", "")
            leave.username = leave.username.replace("\n", "")
        except AttributeError:
            # If reason field is None or not a string, handle the exception
            reason = leave.reason
            leave.status = leave.status
        all_leaves.append({
            'LeaveId': leave.LeaveId,
            'user_id': leave.user_id,
            'username': leave.username,
            'from_date': leave.from_date,
            'to_date': leave.to_date,
            'reason': reason,
            'status': leave.status
        })

    # Get leaves count for the specified date
    leaves_count = len(all_leaves)

    return jsonify({'all_leaves': all_leaves, 'all_leave_count': leaves_count})


# Pending Leave count from date to date
@app.route('/pending_leaves_data', methods=['GET'])
@jwt_required()
def get_pending_leaves_data():
    try:
        current_admin_email = get_jwt_identity()

        admin = Admin.query.filter_by(Email=current_admin_email).first()
        if not admin:
            return jsonify({'message': 'Admin not found'}), 404

        start_date_str = request.args.get('start_date')
        end_date_str = request.args.get('end_date')


        start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d')


        pending_leaves_query = Leaves.query.filter(
            func.date(Leaves.from_date) >= start_date.date(),
            func.date(Leaves.to_date) <= end_date.date(),
            Leaves.status == 'pending'
        )


        pending_leaves_count = pending_leaves_query.count()


        pending_leaves = pending_leaves_query.all()


        pending_leaves_data = []
        for leave in pending_leaves:
            leave_data = {
                'LeaveId': leave.LeaveId,
                'user_id': leave.user_id,
                'username': leave.username,
                'from_date': leave.from_date,
                'to_date': leave.to_date,
                'reason': leave.reason,
                'status': leave.status
            }
            pending_leaves_data.append(leave_data)

        return jsonify({'pending_leaves': pending_leaves_data, 'pending_leaves_count': pending_leaves_count}), 200

    except Exception as e:
        return jsonify({"message": "Error fetching pending leaves data"}), 500


# Get Rejected leaves count from date and to date

@app.route('/rejected_leaves_data', methods=['GET'])
@jwt_required()
def get_rejected_leaves_data():
    try:
        current_admin_email = get_jwt_identity()

        # Check if the user is an admin
        admin = Admin.query.filter_by(Email=current_admin_email).first()
        if not admin:
            return jsonify({'message': 'Admin not found'}), 404

        # Retrieve start_date and end_date from request arguments
        start_date_str = request.args.get('start_date')
        end_date_str = request.args.get('end_date')

        # Check if both start_date and end_date are provided
        if not start_date_str or not end_date_str:
            return jsonify({"message": "Start date and end date are required."}), 400

        # Strip leading and trailing whitespace from date strings
        start_date_str = start_date_str.strip()
        end_date_str = end_date_str.strip()

        # Convert date strings to datetime objects
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d')

        # Query rejected leaves within the specified date range
        rejected_leaves_query = Leaves.query.filter(
            func.date(Leaves.from_date) >= start_date.date(),
            func.date(Leaves.to_date) <= end_date.date(),
            Leaves.status == 'rejected'
        )

        # Count rejected leaves
        rejected_leaves_count = rejected_leaves_query.count()

        # Initialize list to store rejected leaves data
        rejected_leaves_data = []

        # Construct response with rejected leaves information
        for leave in rejected_leaves_query:
            leave_data = {
                'LeaveId': leave.LeaveId,
                'user_id': leave.user_id,
                'username': leave.username,
                'from_date': leave.from_date,
                'to_date': leave.to_date,
                'reason': leave.reason,
                'status': leave.status
            }
            rejected_leaves_data.append(leave_data)

        return jsonify({'rejected_leaves_count': rejected_leaves_count, 'rejected_leaves': rejected_leaves_data}), 200

    except ValueError as ve:
        return jsonify({"message": "Invalid date format. Please use YYYY-MM-DD format.", "error": str(ve)}), 400
    except Exception as e:
        return jsonify({"message": "Error fetching rejected leaves data"}), 500


# Leave count from date to date
# Leave count from date to date
@app.route('/total_leaves_data', methods=['GET'])
@jwt_required()
def get_total_leaves_data():
    try:
        current_admin_email = get_jwt_identity()

        admin = Admin.query.filter_by(Email=current_admin_email).first()
        if not admin:
            return jsonify({'message': 'Admin not found'}), 404

        start_date_str = request.args.get('start_date')
        end_date_str = request.args.get('end_date')


        if not start_date_str or not end_date_str:
            return jsonify({"message": "Start date and end date are required."}), 400


        start_date_str = start_date_str.strip()
        end_date_str = end_date_str.strip()


        start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d')


        total_leaves_query = Leaves.query.filter(
            func.date(Leaves.from_date) >= start_date.date(),
            func.date(Leaves.to_date) <= end_date.date()
        )


        total_leaves = []
        for leave in total_leaves_query:
            leave_data = {
                'LeaveId': leave.LeaveId,
                'user_id': leave.user_id,
                'username': leave.username,
                'from_date': leave.from_date,
                'to_date': leave.to_date,
                'reason': leave.reason,
                'status': leave.status
            }
            total_leaves.append(leave_data)

        total_leaves_count = len(total_leaves)

        return jsonify({'total_leaves_count': total_leaves_count, 'total_leaves': total_leaves}), 200

    except ValueError as ve:
        return jsonify({"message": "Invalid date format. Please use YYYY-MM-DD format.", "error": str(ve)}), 400
    except Exception as e:
        return jsonify({"message": "Error fetching total leaves data"}), 500


# Attendance count per day

@app.route('/present_count/<date>', methods=['GET'])
@jwt_required()
def get_present_count(date):
    try:
        current_admin_email = get_jwt_identity()

        # Check if the user is an admin
        admin = Admin.query.filter_by(Email=str(current_admin_email)).first()
        if not admin:
            return jsonify({'message': 'Admin not found'}), 401

        # Convert date string to datetime object
        date_obj = datetime.strptime(date, '%Y-%m-%d')
    except ValueError:
        return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD.'}), 400

    # Format the date for database query
    formatted_date = date_obj.strftime('%Y-%m-%d')

    # Query present data for the specified date
    present_data = Attendance.query.filter(
        func.date(Attendance.login_time) == formatted_date,
        Attendance.status == 'present'
    ).all()

    # Initialize list to store present data
    present_list = []
    for entry in present_data:
        present_info = {
            'user_id': entry.user_id,
            'username': entry.username,
            'login_time': entry.login_time.strftime("%Y-%m-%d %H:%M:%S"),
            'logout_time': entry.logout_time.strftime("%Y-%m-%d %H:%M:%S") if entry.logout_time else None,
            'status': entry.status
        }
        present_list.append(present_info)

    # Count present entries
    present_count = len(present_list)

    return jsonify({'present_count': present_count, 'present_data': present_list}), 200


# Absent count per day

@app.route('/absent_data/<date>', methods=['GET'])
@jwt_required()
def get_absent_data(date):
    try:
        current_user_email = get_jwt_identity()

        # Check if the user is an admin
        admin = Admin.query.filter_by(Email=str(current_user_email)).first()
        if not admin:
            return jsonify({'message': 'Admin not found'}), 401

        date_obj = datetime.strptime(date, '%Y-%m-%d')
    except ValueError:
        return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD.'}), 400

    formatted_date = date_obj.strftime('%Y-%m-%d')

    absent_data = Attendance.query.filter(
        func.date(Attendance.login_time) == formatted_date, Attendance.status == 'absent'
    ).all()

    absent_list = []
    for absent_entry in absent_data:
        absent_info = {
            'user_id': absent_entry.user_id,
            'username': absent_entry.username,
            'login_time': absent_entry.login_time.strftime("%Y-%m-%d %H:%M:%S"),
            'logout_time': absent_entry.logout_time.strftime("%Y-%m-%d %H:%M:%S") if absent_entry.logout_time else None,
            'status': absent_entry.status
        }
        absent_list.append(absent_info)

    absent_count = len(absent_list)

    return jsonify({'absent_count': absent_count, 'absent_data': absent_list}), 200


# absent_count_by_id(from date and to date)
@app.route('/absent_count_by_id/<int:user_id>', methods=['GET'])
@jwt_required()
# @swag_from('GET')
def get_absent_count_by_id(user_id):
    try:
        current_admin_email = get_jwt_identity()

        admin = Admin.query.filter_by(Email=current_admin_email).first()
        if not admin:
            return jsonify({'message': 'Admin not found'}), 404

        start_date_str = request.args.get('start_date')
        end_date_str = request.args.get('end_date')

        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d')

            # Check if start date is less than or equal to end date
            if start_date > end_date:
                return jsonify({"message": "Start date cannot be greater than end date"}), 400

        except ValueError:
            return jsonify({"message": "Invalid date format. Please provide dates in YYYY-MM-DD format"}), 400

        absent_count = Attendance.query.filter_by(user_id=user_id).filter(
            Attendance.login_time >= start_date,
            Attendance.login_time <= end_date,
            Attendance.status == 'absent'
        ).count()

        absent_data = Attendance.query.filter_by(user_id=user_id).filter(
            Attendance.login_time >= start_date,
            Attendance.login_time <= end_date,
            Attendance.status == 'absent'
        ).all()

        absent_list = []
        for absent_entry in absent_data:
            absent_info = {
                'user_id': absent_entry.user_id,
                'username': absent_entry.username,
                'login_time': absent_entry.login_time.strftime("%Y-%m-%d %H:%M:%S"),
                'logout_time': absent_entry.logout_time.strftime(
                    "%Y-%m-%d %H:%M:%S") if absent_entry.logout_time else None,
                'status': absent_entry.status
            }
            absent_list.append(absent_info)

        return jsonify({'absent_count': absent_count, 'absent_data': absent_list}), 200

    except Exception as e:
        return jsonify({"message": "Error fetching absent count for user"}), 400


# present count by user id and from date to date
@app.route('/present_count_by_id/<int:user_id>', methods=['GET'])
@jwt_required()
# @swag_from('GET')
def get_present_count_by_id(user_id):
    try:
        current_admin_email = get_jwt_identity()

        admin = Admin.query.filter_by(Email=current_admin_email).first()
        if not admin:
            return jsonify({'message': 'Admin not found'}), 404

        start_date_str = request.args.get('start_date')
        end_date_str = request.args.get('end_date')

        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d')
        except ValueError:
            return jsonify({'message': 'Invalid date format. Please provide dates in YYYY-MM-DD format.'}), 400

        if start_date > end_date:
            return jsonify({'message': 'Start date cannot be greater than end date.'}), 400

        present_count = Attendance.query.filter_by(user_id=user_id).filter(
            Attendance.login_time >= start_date,
            Attendance.login_time <= end_date,
            Attendance.status == 'present'
        ).count()

        present_data = Attendance.query.filter_by(user_id=user_id).filter(
            Attendance.login_time >= start_date,
            Attendance.login_time <= end_date,
            Attendance.status == 'present'
        ).all()

        present_list = []
        for present_entry in present_data:
            present_info = {
                'user_id': present_entry.user_id,
                'username': present_entry.username,
                'login_time': present_entry.login_time.strftime("%Y-%m-%d %H:%M:%S"),
                'logout_time': present_entry.logout_time.strftime(
                    "%Y-%m-%d %H:%M:%S") if present_entry.logout_time else None,
                'status': present_entry.status
            }
            present_list.append(present_info)

        return jsonify({'present_count': present_count, 'present_data': present_list}), 200

    except Exception as e:
        return jsonify({"message": "Error fetching present count for user"}), 400


# total leave count by id
@app.route('/total_leave_count_by_id/<int:user_id>', methods=['GET'])
@jwt_required()
def get_total_leave_count_by_id(user_id):
    try:
        current_admin_email = get_jwt_identity()
        admin = Admin.query.filter_by(Email=current_admin_email).first()
        if not admin:
            return jsonify({'message': 'Admin not found'}), 404

        start_date_str = request.args.get('start_date')
        end_date_str = request.args.get('end_date')

        if not start_date_str or not end_date_str:
            return jsonify({"message": "Start date and end date are required."}), 400

        start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()

        total_leave_count = Leaves.query.filter(
            Leaves.user_id == user_id,
            func.date(Leaves.from_date) >= start_date_str,
            func.date(Leaves.to_date) <= end_date_str,
            Leaves.status == 'approved'
        ).count()

        leave_data = Leaves.query.filter(
            Leaves.user_id == user_id,
            func.date(Leaves.from_date) >= start_date_str,
            func.date(Leaves.to_date) <= end_date_str,
            Leaves.status == 'approved'
        ).all()

        leave_list = [
            {
                'LeaveId': leave.LeaveId,
                'user_id': leave.user_id,
                'username': leave.username,
                'from_date': leave.from_date,
                'to_date': leave.to_date,
                'reason': leave.reason,
                'status': leave.status
            }
            for leave in leave_data
        ]

        return jsonify({'total_leave_count': total_leave_count, 'leave_data': leave_list}), 200

    except ValueError as ve:
        return jsonify({"message": "Invalid date format. Please use YYYY-MM-DD format.", "error": str(ve)}), 400
    except Exception as e:
        return jsonify({"message": "Error fetching total leave count for user", "error": str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True,port=5000)
