from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from functools import wraps
from datetime import date
import os

from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Integer, Table, Column, ForeignKey
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_gravatar import Gravatar

from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL

from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar

def admin_only(function):
    @wraps(function)
    def wrapper_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.id != 1:
            return abort(403)
        # else:
        return function(*args, **kwargs)
    return wrapper_function


# def admin_only(function):
#     @wraps(function)
#     def wrapper_function(*args, **kwargs):
#         try:
#             user_id = current_user.id
#             if user_id == 3:
#                 return function(*args, **kwargs)
#         except AttributeError:
#             return abort(403)
#         else:
#             return abort(404)
#     return wrapper_function


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///blog.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

##CONFIGURE TABLES



class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    # below not in the form
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")
# db.create_all()


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(Integer, ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    comments = relationship("Comment", back_populates="comment_to_blog")
# db.create_all()


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(250), nullable=False)
    author_id = db.Column(Integer, ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")
    blog_id = db.Column(Integer, ForeignKey("blog_posts.id"))
    comment_to_blog = relationship("BlogPost", back_populates="comments")
db.create_all()


gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, current_user=current_user)


@app.route('/register', methods=["POST", "GET"])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        new_user_email = register_form.email.data
        new_user_name = register_form.name.data
        new_user_password_raw = register_form.password.data
        print(new_user_password_raw)
        new_user_password_hashed = generate_password_hash(password=new_user_password_raw,
                                                          method="pbkdf2:sha256",
                                                          salt_length=8)
        new_user = User(
            email=new_user_email,
            name=new_user_name,
            password=new_user_password_hashed
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=register_form, current_user=current_user)


@app.route('/login', methods=["POST", "GET"])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        email_to_verify = login_form.email.data
        pw_to_verify = login_form.password.data
        user = User.query.filter_by(email=email_to_verify).first()
        if user:
            if check_password_hash(pwhash=user.password, password=pw_to_verify):
                print("yes")
                login_user(user)
                # flash("Logged in successfully.")
                return redirect(url_for("get_all_posts"))
            else:
                print("no1")
                flash("Wrong Password.")
        else:
            print("no2")
            flash("User does not exist.")
    return render_template("login.html", form=login_form, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


# @app.route("/post/<int:post_id>", methods=["POST","GET"])
# def show_post(post_id):
#     comment_form = CommentForm()
#     requested_post = BlogPost.query.get(post_id)
#     comments_from_db = Comment.query.get(post_id)
#     if current_user.is_authenticated:
#         if comment_form.validate_on_submit():
#             new_comment = Comment(
#                 text=comment_form.comment.data
#             )
#             db.session.add(new_comment)
#             db.session.commit()
#             return redirect(url_for("show_post", post_id=requested_post.id))
#     else:
#         flash("Please login.")
#
#     return render_template("post.html", post=requested_post,
#                            current_user=current_user, form=comment_form, comments=comments_from_db)


@app.route("/post/<int:post_id>", methods=["POST","GET"])
def show_post(post_id):
    comment_form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    comments_from_db = Comment.query.get(post_id)
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("Please login.")
            return redirect(url_for("login"))
        else:
            new_comment = Comment(
                text=comment_form.comment.data,
                comment_author=current_user,
                comment_to_blog=requested_post
            )
            db.session.add(new_comment)
            db.session.commit()
            print(comments_from_db)
    return render_template("post.html", post=requested_post,
                           current_user=current_user, form=comment_form)


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)


@app.route("/contact")
def contact():
    return render_template("contact.html", current_user=current_user)


@app.route("/new-post", methods=["POST", "GET"])
# @admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user)


@app.route("/edit-post/<int:post_id>")
@login_required
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, current_user=current_user)


@app.route("/delete/<int:post_id>")
@login_required
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
