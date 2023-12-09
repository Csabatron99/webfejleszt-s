from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect, CSRFError
from wtforms import StringField, SelectField, SubmitField, PasswordField, TextAreaField
from wtforms.validators import DataRequired
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
from flask_migrate import Migrate
from flask_login import current_user, login_user
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['WTF_CSRF_ENABLED'] = True

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

csrf = CSRFProtect(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    user_type = db.Column(db.String(10), default='normal')

    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)
    def get_timeout(self):
        if self.user_type == 'admin':
            return int(timedelta(minutes=30).total_seconds())
        elif self.user_type == 'editor':
            return int(timedelta(minutes=15).total_seconds())
        else:
            return None  # Use the default Flask session behavior



class Record(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)

def get_records():
    return Record.query.all()
    
class AddRecordForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Submit')

class EditRecordForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Submit')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    user_type = SelectField('User Type', choices=[('normal', 'Normal'), ('editor', 'Editor'), ('admin', 'Admin')], validators=[DataRequired()])
    submit = SubmitField('Register')
    
class EditUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    user_type = SelectField('User Type', choices=[('normal', 'Normal'), ('editor', 'Editor'), ('admin', 'Admin')], validators=[DataRequired()])
    submit = SubmitField('Save Changes')

class DeleteUserForm(FlaskForm):
    submit = SubmitField('Delete User')
    
class AddUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    user_type = SelectField('User Type', choices=[('normal', 'Normal'), ('editor', 'Editor'), ('admin', 'Admin')], validators=[DataRequired()])
    submit = SubmitField('Add User')

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return render_template('csrf_error.html', reason=e.description), 400

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/home')
def home():
    if current_user.is_authenticated:
        return render_template('home.html')
    else:
        return redirect(url_for('index'))

@app.route('/user_database')
@login_required
def user_database():
    search_term = request.args.get('search', '')
    # Check if the current user is an admin
    if current_user.user_type != 'admin':
        flash('You do not have permission to access the user database.', 'danger')
        return redirect(url_for('home'))

    users = User.query.all()
    if search_term:
        users = [user for user in users if search_term.lower() in user.username.lower()]
    add_user_form = AddUserForm()
    return render_template('user_database.html', users=users, add_user_form=add_user_form)

@app.route('/records')
@login_required
def records():
    if current_user.user_type in ['normal','editor', 'admin']:
        search_term = request.args.get('search', '')
        # Retrieve records and render the template
        records = get_records()  # You should replace this with your actual function to get records
        if search_term:
            records = [record for record in records if search_term.lower() in record.title.lower() or search_term.lower() in record.content.lower()]
        add_record_form = AddRecordForm()
        edit_record_form = EditRecordForm()  # Create an instance of the EditRecordForm
        return render_template('records.html', records=records, add_record_form=add_record_form, edit_record_form=edit_record_form, search_term=search_term)
    else:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('home'))


@app.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    # Check if the current user is an admin
    if current_user.user_type != 'admin':
        flash('You do not have permission to add users.', 'danger')
        return redirect(url_for('user_database'))

    form = AddUserForm()

    if form.validate_on_submit():
        # Create a new user with hashed password
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(
            username=form.username.data,
            password=hashed_password,
            user_type=form.user_type.data
        )

        db.session.add(new_user)
        db.session.commit()

        flash('User added successfully!', 'success')
        return redirect(url_for('user_database'))

    return render_template('add_user.html', form=form)

@app.route('/edit_user/<int:user_id>', methods=['POST'])
@login_required
def edit_user(user_id):
    # Check if the current user is an admin
    if current_user.user_type != 'admin':
        flash('You do not have permission to edit users.', 'danger')
        return redirect(url_for('user_database'))

    # Fetch the user to be edited
    user = User.query.get(user_id)

    # Check if the user exists
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('user_database'))

    # Update the user information
    user.username = request.form['edit_username']
    user.user_type = request.form['edit_user_type']

    # Commit the changes to the database
    db.session.commit()

    flash('User updated successfully!', 'success')
    return redirect(url_for('user_database'))


@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    # Check if the current user is an admin
    if current_user.user_type != 'admin':
        flash('You do not have permission to delete users.', 'danger')
        return redirect(url_for('user_database'))

    # Fetch the user to be deleted
    user = User.query.get(user_id)

    # Check if the user exists
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('user_database'))

    # Delete the user from the database
    db.session.delete(user)
    db.session.commit()

    flash('User deleted successfully!', 'success')
    return redirect(url_for('user_database'))

@app.route('/add_record', methods=['POST'])
@login_required
def add_record():
    form = AddRecordForm()

    if form.validate_on_submit():
        new_record = Record(title=form.title.data, content=form.content.data)
        db.session.add(new_record)
        db.session.commit()
        return redirect(url_for('records'))

    return jsonify(errors=form.errors)

@app.route('/edit_record/<int:record_id>', methods=['POST'])
@login_required
def edit_record(record_id):
    record = Record.query.get_or_404(record_id)
    form = EditRecordForm(request.form)

    if form.validate_on_submit():
        # Process the form data
        record.title = form.title.data
        record.content = form.content.data
        db.session.commit()

        flash('Record updated successfully!', 'success')
        return redirect(url_for('records'))
    else:
        flash('There was an error updating the record. Please try again.', 'danger')
        return render_template('csrf_error.html'), 400

@app.route('/delete_record/<int:record_id>', methods=['POST'])
@login_required
def delete_record(record_id):
    record = Record.query.get_or_404(record_id)
    db.session.delete(record)
    db.session.commit()
    return redirect(url_for('records'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user_type = form.user_type.data

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        new_user = User(username=username, password=hashed_password, user_type=user_type)
        db.session.add(new_user)
        db.session.commit()

        flash('Your account has been created!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if user and user.check_password(form.password.data):
            login_user(user)

            # Set user_type in the session
            session['user_type'] = user.user_type

            flash('Login successful!', 'success')
            return redirect(url_for('home'))

        flash('Login failed. Please check your username and password.', 'danger')

    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
    
migrate = Migrate(app, db)