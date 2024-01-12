from quart import Quart, request, jsonify, g
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from datetime import datetime, timedelta
from quart_auth import login_user, logout_user, login_required, current_user
from passlib.hash import bcrypt 
from jose import jwt

DATABASE_URL = "postgresql://kairidev:l0ajmyo6qbDJ@ep-autumn-flower-96499455.us-east-2.aws.neon.tech/please2?sslmode=require"

app = Quart(__name__)
app.config["SECRET_KEY"] = "key"
app.config["JWT_EXPIRATION_DELTA"] = timedelta(minutes=15)
# Create a SQLAlchemy engine
engine = create_engine(DATABASE_URL)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(20), unique=True, nullable=True)
    email = Column(String(120), unique=True, nullable=True)
    password = Column(String(255), nullable=True)
    bio = Column(String(200))
    profile_image = Column(String(20), nullable=True, default='default.jpg')
    posts = relationship('Post', back_populates='user', lazy=True, cascade='all, delete-orphan')  
    comments = relationship('Comment', back_populates='comment_user', lazy=True, cascade='all, delete-orphan') 
    date_created = Column(DateTime, nullable=True, default=datetime.utcnow)

class Post(Base):
    __tablename__ = 'posts'

    id = Column(Integer, primary_key=True, index=True)
    content = Column(Text, nullable=False)
    image = Column(String(20), nullable=False, default='default.jpg')
    caption = Column(String(100))
    date_posted = Column(DateTime, nullable=False)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    user = relationship('User', back_populates='posts')
    comments = relationship('Comment', back_populates='post', lazy=True, cascade='all, delete-orphan') 

class Comment(Base):
    __tablename__ = 'comments'

    id = Column(Integer, primary_key=True, index=True)
    content = Column(Text, nullable=False)
    date_commented = Column(DateTime, nullable=False, default=datetime.utcnow)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    post_id = Column(Integer, ForeignKey('posts.id'), nullable=False)
    comment_user = relationship('User', back_populates='comments')
    post = relationship('Post', back_populates='comments')

Base.metadata.create_all(bind=engine)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def create_jwt(user):
    expiration_time = datetime.utcnow() + app.config["JWT_EXPIRATION_DELTA"]
    payload = {
        "sub": str(user.id),
        "exp": expiration_time,
    }
    return jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")

# Dependency to get the database session
def get_db():
    db = SessionLocal()
    try:
        return db
    except Exception as e:
        db.rollback()
        raise
    finally:
        db.close()

@app.route("/register", methods=['POST'])
async def register():
    session = Session()

    data = await request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return {'message': 'Incomplete registration data'}, 400

    hashed_password = bcrypt.hash(password)
    user = User(username=username, email=email, password=hashed_password)

    db = get_db()
    db.add(user)
    db.commit()
    db.refresh(user)
    db.close()


    return {'message': 'Registration successful', "User": user.username}, 201

@app.route("/login", methods=["POST"])
async def login():
    data = await request.get_json()
    username = data.get("username")
    password = data.get("password")

    # Retrieve the user from the database
    db = get_db()
    user = db.query(User).filter(User.username == username).first()

    if user and bcrypt.verify(password, user.password):
        token = create_jwt(user)
        return jsonify({"message": "Login successful", "token": token, "User": user.username})
    else:
        return jsonify({"message": "Invalid credentials"}), 401

@app.route("/logout", methods=["POST"])
async def logout():
    g.pop("user", None)
    return jsonify({"message": "Logout successful"})


@app.route("/edit_profile", methods=["PUT"])
async def edit_profile():
    if "user" not in g:
        return jsonify({"message": "Unauthorized"}), 401

    data = await request.get_json()
    bio = data.get("bio")
    profile_image = data.get("profile_image")

    # Update user's bio and profile image
    g.user.bio = bio
    g.user.profile_image = profile_image

    db = get_db()
    db.add(g.user)
    db.commit()

    return jsonify({"message": "Profile updated successfully"})

@app.route("/user/<username>", methods=["GET"])
async def get_user(username):
    db = get_db()
    user = db.query(User).filter(User.username == username).first()

    if not user:
        return jsonify({"message": "User not found"}), 404

    user_data = {
        "username": user.username,
        "bio": user.bio,
        "posts": [{"content": post.content, "date_posted": post.date_posted} for post in user.posts]
    }

    return jsonify(user_data)


@app.route("/delete_profile", methods=["DELETE"])
async def delete_profile():
    if "user" not in g:
        return jsonify({"message": "Unauthorized"}), 401

    db = get_db()
    db.delete(g.user)
    db.commit()

    g.pop("user", None)  # Clear user from g object

    return jsonify({"message": "Profile deleted successfully"})

@app.route("/create_post", methods=["POST"])
async def create_post():
    if "user" not in g:
        return jsonify({"message": "Unauthorized"}), 401

    data = await request.get_json()
    content = data.get("content")
    image = data.get("image")
    caption = data.get("caption")

    new_post = Post(
        content=content,
        image=image,
        caption=caption,
        date_posted=datetime.utcnow(),
        user=g.user
    )

    db = get_db()
    db.add(new_post)
    db.commit()

    return jsonify({"message": "Post created successfully"})

@app.route("/edit_post/<int:post_id>", methods=["PUT"])
async def edit_post(post_id):
    if "user" not in g:
        return jsonify({"message": "Unauthorized"}), 401

    db = get_db()
    post = db.query(Post).filter(Post.id == post_id, Post.user_id == g.user.id).first()

    if not post:
        return jsonify({"message": "Post not found or unauthorized to edit"}), 404

    data = await request.get_json()
    content = data.get("content")
    image = data.get("image")
    caption = data.get("caption")

    post.content = content
    post.image = image
    post.caption = caption

    db.commit()

    return jsonify({"message": "Post edited successfully"})

@app.route('/all_posts', methods=['GET'])
async def get_posts():
    db = get_db()
    posts = db.query(Post).order_by(Post.date_posted.desc()).all()

    posts_list = [{"id": post.id, "content": post.content, "image": post.image,
                    "caption": post.caption, "date_posted": post.date_posted,
                    "user_id": post.user_id} for post in posts]

    return jsonify(posts_list)

@app.route("/delete_post/<int:post_id>", methods=["DELETE"])
async def delete_post(post_id):
    if "user" not in g:
        return jsonify({"message": "Unauthorized"}), 401

    db = get_db()
    post = db.query(Post).filter(Post.id == post_id, Post.user_id == g.user.id).first()

    if not post:
        return jsonify({"message": "Post not found or unauthorized to delete"}), 404

    db.delete(post)
    db.commit()

    return jsonify({"message": "Post deleted successfully"})

@app.route("/like_post/<int:post_id>", methods=["POST"])
async def like_post(post_id):
    if "user" not in g:
        return jsonify({"message": "Unauthorized"}), 401

    db = get_db()
    post = db.query(Post).filter(Post.id == post_id).first()

    if not post:
        return jsonify({"message": "Post not found"}), 404

    if g.user in post.liked_by:
        return jsonify({"message": "Post already liked"}), 400

    post.liked_by.append(g.user)
    db.commit()

    return jsonify({"message": "Post liked successfully"})

@app.route("/unlike_post/<int:post_id>", methods=["POST"])
async def unlike_post(post_id):
    if "user" not in g:
        return jsonify({"message": "Unauthorized"}), 401

    db = get_db()
    post = db.query(Post).filter(Post.id == post_id).first()

    if not post:
        return jsonify({"message": "Post not found"}), 404

    if g.user not in post.liked_by:
        return jsonify({"message": "Post not liked"}), 400

    post.liked_by.remove(g.user)
    db.commit()

    return jsonify({"message": "Post unliked successfully"})

@app.route("/comment_post/<int:post_id>", methods=["POST"])
async def comment_post(post_id):
    if "user" not in g:
        return jsonify({"message": "Unauthorized"}), 401

    data = await request.get_json()
    content = data.get("content")

    db = get_db()
    post = db.query(Post).filter(Post.id == post_id).first()

    if not post:
        return jsonify({"message": "Post not found"}), 404

    new_comment = Comment(
        content=content,
        date_commented=datetime.utcnow(),
        user=g.user,
        post=post
    )

    db.add(new_comment)
    db.commit()

    return jsonify({"message": "Comment added successfully"})

# Run the app
if __name__ == "__main__":
    app.run()
