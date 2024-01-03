from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, SubmitField
from wtforms.validators import InputRequired, Length, Regexp, EqualTo
from flask_wtf.file import FileField
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import os
import time
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask import abort


app = Flask(__name__)
db = SQLAlchemy()
app.secret_key = '123'  # Replace with your unique secret key
UPLOAD_FOLDER = 'files'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'doc', 'docx', 'pptx', 'xls', 'py', 'bat', 'jvs'}

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    status = db.Column(db.String(10), nullable=False)  # 'Admin' or 'User'
    account_status = db.Column(db.String(10), nullable=True, default='goodOne')  # 'banned', 'unbanned', 'goodOne'



class UpdateStatusForm(FlaskForm):
    new_status = SelectField('New Status', choices=[('banned', 'Banned'), ('unbanned', 'Unbanned'), ('goodOne', 'Good One')], validators=[InputRequired()])
    submit = SubmitField('Update Status')


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('files', lazy=True))

# Create the tables if they don't exist
with app.app_context():
    db.create_all()


# Define the forms
class UploadForm(FlaskForm):
    file = FileField('Choose File')
    submit = SubmitField('Upload')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20), Regexp('^\w+$', message="Username must contain only letters, numbers, and underscores.")])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=4, max=20), Regexp('^[A-Za-z0-9]+$')])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password', message='Passwords must match')])
    status = SelectField('Status', choices=[('User', 'User')], validators=[InputRequired()])
    submit = SubmitField('Register')


class CreateAdminForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20), Regexp('^\w+$', message="Username must contain only letters, numbers, and underscores.")])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=4, max=20), Regexp('^[A-Za-z0-9]+$')])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password', message='Passwords must match')])
    status = SelectField('Status', choices=[('User', 'User'), ('Admin', 'Admin')], validators=[InputRequired()])
    submit = SubmitField('Create Admin Account')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')

# main screen functions ->

@app.route('/')
def index():
    user = None
    upload_form = UploadForm()

    if 'user_id' in session:
        user = User.query.get(session['user_id'])

    return render_template('index.html', user=user, upload_form=upload_form)


# super admin funcs ->

@app.route('/create_admin', methods=['GET', 'POST'])
def create_admin():
    if 'user_id' not in session:
        return redirect(url_for('index'))

    superadmin = User.query.get(session['user_id'])

    if superadmin.status != 'SuperAdmin':
        # If the user is not a SuperAdmin, deny access
        abort(403)

    form = CreateAdminForm()

    try:
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data
            hashed_password = generate_password_hash(password)
            status = form.status.data

            new_admin = User(username=username, password=hashed_password, status=status)
            db.session.add(new_admin)
            db.session.commit()

            flash(f'Admin account {new_admin.username} created successfully.', 'success')
            return redirect(url_for('admin_users'))
    except:
        flash('User with this name already exists.', 'failure')

    return render_template('create_admin.html', form=form)



@app.route('/admin_users')
def SuperAdmin_users():
    if 'user_id' not in session:
        return redirect(url_for('index'))

    user = User.query.get(session['user_id'])

    if user.status != 'SuperAdmin':
        # If the user is not an admin, deny access
        abort(403)

    users = User.query.all()
    return render_template('SuperAdmin_users.html', user=user, users=users)




# admin funcs ->

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('index'))

    user = User.query.get(session['user_id'])

    if user.status != 'Admin' and user.status != 'SuperAdmin':
        # Если пользователь не администратор, запретить доступ
        abort(403)

    files = get_files()
    return render_template('filesAdmin.html', user=user, files=files)


@app.route('/admin_delete_file/<int:file_id>')
def admin_delete_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('index'))

    user = User.query.get(session['user_id'])

    if user.status != 'Admin' and user.status != 'SuperAdmin':
        # Если пользователь не администратор, запретить доступ
        abort(403)

    file_to_delete = File.query.get(file_id)

    if file_to_delete:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_to_delete.name)
        os.remove(file_path)
        
        db.session.delete(file_to_delete)
        db.session.commit()

        flash(f'File {file_to_delete.name} deleted successfully.', 'success')
    else:
        flash('File not found.', 'danger')

    return redirect(url_for('admin_dashboard'))


@app.route('/admin_users')
def admin_users():
    if 'user_id' not in session:
        return redirect(url_for('index'))

    user = User.query.get(session['user_id'])

    if user.status != 'Admin' and user.status != 'SuperAdmin':
        # If the user is not an admin, deny access
        abort(403)

    users = User.query.all()
    return render_template('admin_users.html', user=user, users=users)


@app.route('/admin_delete_user/<int:user_id>')
def admin_delete_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('index'))

    admin = User.query.get(session['user_id'])

# Prevent SuperAdmin from deleting other SuperAdmins
    if user_to_delete and user_to_delete.status == 'SuperAdmin':
        abort(403)

    if user_to_delete and user_to_delete.status == 'User':
        db.session.delete(user_to_delete)
        db.session.commit()

        flash(f'User {user_to_delete.username} deleted successfully.', 'success')
    elif not user_to_delete:
        flash('User not found.', 'danger')

    return redirect(url_for('admin_users'))


@app.route('/admin_update_status/<int:user_id>', methods=['GET', 'POST'])
def admin_update_status(user_id):
    if 'user_id' not in session:
        return redirect(url_for('index'))

    admin = User.query.get(session['user_id'])
    user_to_update = User.query.get(user_id)  # Исправленная строка

    # Prevent Admin from banning SuperAdmin or Admin
    if admin.status == 'Admin' and user_to_update.status in ['Admin', 'SuperAdmin']:
        abort(403)

    form = UpdateStatusForm()

    if form.validate_on_submit():
        new_status = form.new_status.data
        user_to_update.account_status = new_status


        db.session.commit()
        flash(f'Status of {user_to_update.username} updated to {new_status}.', 'success')

    return render_template('admin_update_status.html', user=admin, user_to_update=user_to_update, form=form)





# acc functions ->

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password) and user.account_status != 'banned':
            # Check if the account is not banned
            session['user_id'] = user.id
            flash('Successful Login', 'success')
            return redirect(url_for('index'))
        elif user and user.account_status == 'banned':
            flash('Your account is banned. Contact an administrator for assistance.', 'danger')
        else:
            flash('Invalid credentials', 'danger')

    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))



@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    try:
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data
            hashed_password = generate_password_hash(password)
            status = form.status.data

            new_user = User(username=username, password=hashed_password, status=status)
            db.session.add(new_user)
            db.session.commit()

            flash('Registration successful. You can now log in.', 'success')
            return redirect(url_for('login'))
    except Exception as e:
        flash('Something goes wrong. Try again.', 'failure')

    return render_template('register.html', form=form)





# files fuctions ->

def allowed_file(filename):
    return '.' in filename

def get_files():
    files = File.query.all()
    return files


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        return redirect(url_for('index'))

    user = User.query.get(session['user_id'])

    if user.account_status == 'banned':
        flash('Your account is banned. Contact an administrator for assistance.', 'danger')
        return redirect(url_for('index'))

    uploaded_file = request.files['file']

    if uploaded_file.filename != '' and allowed_file(uploaded_file.filename):
        timestamp = datetime.utcnow()
        filename = secure_filename(f"{timestamp}_{uploaded_file.filename}")
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        uploaded_file.save(file_path)

        new_file = File(name=filename, timestamp=timestamp, user_id=session['user_id'])
        db.session.add(new_file)
        db.session.commit()

        flash(f'File uploaded successfully. Path: {file_path}', 'success')

    return redirect(url_for('index'))

@app.route('/files')
def view_files():
    if 'user_id' not in session:
        return redirect(url_for('index'))

    elif 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            status = user.status
    files = get_files()
    if status == 'Admin':
        return render_template('filesAdmin.html', files=files)
    else:
        return render_template('files.html', files=files)

@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)

    app.run(debug=True)