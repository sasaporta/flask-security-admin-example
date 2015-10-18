# Example of combining Flask-Security and Flask-Admin.
# by Steve Saporta
# April 15, 2014
#
# Uses Flask-Security to control access to the application, with "admin" and "end-user" roles.
# Uses Flask-Admin to provide an admin UI for the lists of users and roles.
# SQLAlchemy ORM, Flask-Mail and WTForms are used in supporting roles, as well.

from flask import Flask, render_template
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.security import current_user, login_required, RoleMixin, Security, \
    SQLAlchemyUserDatastore, UserMixin, utils
from flask_mail import Mail
from flask.ext.admin import Admin
from flask.ext.admin.contrib import sqla

from wtforms.fields import PasswordField

# Initialize Flask and set some config values
app = Flask(__name__)
app.config['DEBUG']=True
# Replace this with your own secret key
app.config['SECRET_KEY'] = 'super-secret'
# The database must exist (although it's fine if it's empty) before you attempt to access any page of the app
# in your browser.
# I used a PostgreSQL database, but you could use another type of database, including an in-memory SQLite database.
# You'll need to connect as a user with sufficient privileges to create tables and read and write to them.
# Replace this with your own database connection string.
#xxxxx
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:xxxxxxxx@localhost/flask_example'

# Set config values for Flask-Security.
# We're using PBKDF2 with salt.
app.config['SECURITY_PASSWORD_HASH'] = 'pbkdf2_sha512'
# Replace this with your own salt.
app.config['SECURITY_PASSWORD_SALT'] = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'

# Flask-Security optionally sends email notification to users upon registration, password reset, etc.
# It uses Flask-Mail behind the scenes.
# Set mail-related config values.
# Replace this with your own "from" address
app.config['SECURITY_EMAIL_SENDER'] = 'no-reply@example.com'
# Replace the next five lines with your own SMTP server settings
app.config['MAIL_SERVER'] = 'email-smtp.us-west-2.amazonaws.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'xxxxxxxxxxxxxxxxxxxx'
app.config['MAIL_PASSWORD'] = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'

# Initialize Flask-Mail and SQLAlchemy
mail = Mail(app)
db = SQLAlchemy(app)

# Create a table to support a many-to-many relationship between Users and Roles
roles_users = db.Table(
    'roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
)


# Role class
class Role(db.Model, RoleMixin):

    # Our Role has three fields, ID, name and description
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

    # __str__ is required by Flask-Admin, so we can have human-readable values for the Role when editing a User.
    # If we were using Python 2.7, this would be __unicode__ instead.
    def __str__(self):
        return self.name

    # __hash__ is required to avoid the exception TypeError: unhashable type: 'Role' when saving a User
    def __hash__(self):
        return hash(self.name)


# User class
class User(db.Model, UserMixin):

    # Our User has six fields: ID, email, password, active, confirmed_at and roles. The roles field represents a
    # many-to-many relationship using the roles_users table. Each user may have no role, one role, or multiple roles.
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    roles = db.relationship(
        'Role',
        secondary=roles_users,
        backref=db.backref('users', lazy='dynamic')
    )


# Initialize the SQLAlchemy data store and Flask-Security.
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)


# Executes before the first request is processed.
@app.before_first_request
def before_first_request():

    # Create any database tables that don't exist yet.
    db.create_all()

    # Create the Roles "admin" and "end-user" -- unless they already exist
    user_datastore.find_or_create_role(name='admin', description='Administrator')
    user_datastore.find_or_create_role(name='end-user', description='End user')

    # Create two Users for testing purposes -- unless they already exists.
    # In each case, use Flask-Security utility function to encrypt the password.
    encrypted_password = utils.encrypt_password('password')
    if not user_datastore.get_user('someone@example.com'):
        user_datastore.create_user(email='someone@example.com', password=encrypted_password)
    if not user_datastore.get_user('admin@example.com'):
        user_datastore.create_user(email='admin@example.com', password=encrypted_password)

    # Commit any database changes; the User and Roles must exist before we can add a Role to the User
    db.session.commit()

    # Give one User has the "end-user" role, while the other has the "admin" role. (This will have no effect if the
    # Users already have these Roles.) Again, commit any database changes.
    user_datastore.add_role_to_user('someone@example.com', 'end-user')
    user_datastore.add_role_to_user('admin@example.com', 'admin')
    db.session.commit()


# Displays the home page.
@app.route('/')
# Users must be authenticated to view the home page, but they don't have to have any particular role.
# Flask-Security will display a login form if the user isn't already authenticated.
@login_required
def index():
    return render_template('index.html')


# Customized User model for SQL-Admin
class UserAdmin(sqla.ModelView):

    # Don't display the password on the list of Users
    column_exclude_list = ('password',)

    # Don't include the standard password field when creating or editing a User (but see below)
    form_excluded_columns = ('password',)

    # Automatically display human-readable names for the current and available Roles when creating or editing a User
    column_auto_select_related = True

    # Prevent administration of Users unless the currently logged-in user has the "admin" role
    def is_accessible(self):
        return current_user.has_role('admin')

    # On the form for creating or editing a User, don't display a field corresponding to the model's password field.
    # There are two reasons for this. First, we want to encrypt the password before storing in the database. Second,
    # we want to use a password field (with the input masked) rather than a regular text field.
    def scaffold_form(self):

        # Start with the standard form as provided by Flask-Admin. We've already told Flask-Admin to exclude the
        # password field from this form.
        form_class = super(UserAdmin, self).scaffold_form()

        # Add a password field, naming it "password2" and labeling it "New Password".
        form_class.password2 = PasswordField('New Password')
        return form_class

    # This callback executes when the user saves changes to a newly-created or edited User -- before the changes are
    # committed to the database.
    def on_model_change(self, form, model, is_created):

        # If the password field isn't blank...
        if len(model.password2):

            # ... then encrypt the new password prior to storing it in the database. If the password field is blank,
            # the existing password in the database will be retained.
            model.password = utils.encrypt_password(model.password2)


# Customized Role model for SQL-Admin
class RoleAdmin(sqla.ModelView):

    # Prevent administration of Roles unless the currently logged-in user has the "admin" role
    def is_accessible(self):
        return current_user.has_role('admin')

# Initialize Flask-Admin
admin = Admin(app)

# Add Flask-Admin views for Users and Roles
admin.add_view(UserAdmin(User, db.session))
admin.add_view(RoleAdmin(Role, db.session))


# If running locally, listen on all IP addresses, port 8080
if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=int('8080'),
        debug=app.config['DEBUG']
    )
