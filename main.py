import os
import webapp2
import jinja2
import hashlib
import hmac
import random
import string
import re

from google.appengine.ext import ndb

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")  # RE for Username
PASS_RE = re.compile(r"^.{3,20}$")  # RE for Password
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")  # RE for Email
SECRET = "zb,n-vL= |a8bg}xcF{:rC<+9omP^T"


def check_user(u):
    """Validation for Username"""
    return USER_RE.match(u)


def check_pass(p):
    """Validation for Password"""
    return PASS_RE.match(p)


def check_email(e):
    """Validation for Email"""
    return EMAIL_RE.match(e)


def hash_str(s):
    """HMAC Hashing for Cookies"""
    return hmac.new(SECRET, s).hexdigest()


def make_secure_val(s):
    """Secure value of Cookie using HMAC Hashing"""
    return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):
    """Validating secure value of Cookie using HMAC Hashing"""
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val


def make_salt():
    """Salt generation for password's SHA256 hashing"""
    return ''.join(random.choice(string.letters) for x in xrange(5))


def make_pw_hash(name, pw, salt=None):
    """SHA256 Hashing of password"""
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)


def valid_pw(name, pw, h):
    """Validating SHA256 Hashed password"""
    salt = h.split(',')[1]
    return h == make_pw_hash(name, pw, salt)


def users_key(group='default'):
    """Defining key for User"""
    return ndb.Key('users', group)


def blog_key(name='default'):
    """Defining key for a single Post of the blog"""
    return ndb.Key('blogs', name)


class User(ndb.Model):
    """Defining User Table"""
    username = ndb.StringProperty(required=True)
    pw_hash = ndb.StringProperty(required=True)
    email = ndb.StringProperty()


class Post(ndb.Model):
    """Defining table of attributes of a single post"""
    subject = ndb.StringProperty(required=True)
    content = ndb.TextProperty(required=True)
    author = ndb.StructuredProperty(User)
    likes = ndb.IntegerProperty(default=0)
    created = ndb.DateTimeProperty(auto_now_add=True)


class Comment(ndb.Model):
    """Defining table for comments"""
    post_id = ndb.IntegerProperty(required=True)
    author = ndb.StructuredProperty(User)
    content = ndb.StringProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)


class Like(ndb.Model):
    """Defining table for likes and dislikes"""
    post_id = ndb.IntegerProperty(required=True)
    author = ndb.StructuredProperty(User)


class BlogHandler(webapp2.RequestHandler):
    """
    Contains general functions for rendering Jinja2 template
    and reading cookies
    """

    def write(self, *a, **kw):
        """A better/short function for writing on page"""
        self.response.out.write(*a, **kw)

    def render_str(self, template, **kw):
        """Fuction to render Jinja2 template"""
        # initializing user cookie whenever a page is rendered
        kw['user'] = self.user
        t = jinja_env.get_template(template)
        return t.render(kw)

    def render(self, template, **kw):
        """Function that writes rendered template to page """
        self.write(self.render_str(template, **kw))

    def read_secure_cookie(self, name):
        """Reading, Validating and Returning HMAC secured cookie"""
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def initialize(self, *a, **kw):
        """Initializes the page with the signed-in user"""
        webapp2.RequestHandler.initialize(self, *a, **kw)
        username = self.read_secure_cookie('user')
        self.user = User.gql("WHERE username='%s'" % username).get()


class Main(BlogHandler):
    """Class to render homepage with latest posts"""
    def get(self):
        posts = Post.gql("ORDER BY created DESC")
        self.render("index.html", posts=posts)


class Signup(BlogHandler):
    """Renders SignUp page and registers new users"""
    def get(self):
        self.render("signup.html")

    def post(self):
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        user_error = pw_error = verify_error = email_error = exist_error = False  # NOQA

        user_exists = User.gql("WHERE username='%s'" % self.username).get()
        if user_exists:
            exist_error = True
            self.render("signup.html",
                        exist_error=exist_error,
                        username=self.username,
                        email=self.email)
        else:
            if not self.username or not check_user(self.username):
                user_error = True  # username is not valid as per USER_RE
            if not self.password or not self.verify or not check_pass(self.password):  # NOQA
                pw_error = True  # password not valid as per PASS_RE
            if self.password != self.verify:
                verify_error = True  # password do not match with the original
            if self.email and not check_email(self.email):
                email_error = True  # email not valid as per EMAIL_RE

            # if there's any error, re-render the page with error message
            if user_error or pw_error or verify_error or email_error:
                self.render("signup.html",
                            user_error=user_error,
                            pw_error=pw_error,
                            verify_error=verify_error,
                            email_error=email_error,
                            username=self.username,
                            email=self.email)

            # if there's no error, add user to db table User
            else:
                user = User(username=self.username,
                            pw_hash=make_pw_hash(self.username, self.password),
                            email=self.email)
                user.put()
                user_cookie = make_secure_val(str(self.username))
                self.response.headers.add_header("Set-Cookie",
                                                 "user=%s; Path=/" % user_cookie)  # NOQA
                self.redirect("/welcome")


class Welcome(BlogHandler):
    """Renders Welcome page using user cookie"""
    def get(self):
        user = self.request.cookies.get('user')
        if user:
            username = check_secure_val(user)
            if username:
                self.render("welcome.html", username=username)
            else:
                self.redirect('/signup')
        else:
            self.redirect('/signup')


class Login(BlogHandler):
    """Renders Login page and makes user cookie"""
    def get(self):
        self.render("login.html")

    def post(self):
        self.username = self.request.get("username")
        self.password = self.request.get("password")
        user = User.gql("WHERE username='%s'" % self.username).get()
        if user and valid_pw(self.username, self.password, user.pw_hash):
            user_cookie = make_secure_val(str(self.username))
            self.response.headers.add_header("Set-Cookie",
                                             "user=%s; Path=/" % user_cookie)
            self.redirect("/welcome")
        else:
            error = "Not a valid username or password"
            self.render("login.html", username=self.username, error=error)


class Logout(BlogHandler):
    """Logs out user and deletes user cookie"""
    def get(self):
        self.response.headers.add_header("Set-Cookie", "user=; Path=/")
        self.redirect("/login")


class NewPost(BlogHandler):
    """Renders newpost page and submit posts to table Post"""
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect("/")
        self.subject = self.request.get("subject")
        self.content = self.request.get("content")
        if self.subject and self.content:
            post = Post(parent=blog_key(),
                        subject=self.subject,
                        content=self.content,
                        author=self.user)
            post.put()
            self.redirect("/%s" % str(post.key.id()))
        else:
            error = "Subject or Content field should not be blank."
            self.render("newpost.html",
                        subject=self.subject,
                        content=self.content,
                        error=error)


class PostPage(BlogHandler):
    """
    Renders the page for a single post, handles comments and likes on post
    """
    def get(self, post_id):
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()
        comments = Comment.gql("WHERE post_id=%s ORDER BY created DESC" % int(post_id))  # NOQA
        liked = None
        if self.user:
            liked = Like.gql("WHERE post_id=:1 AND author.username=:2", int(post_id), self.user.username).get()  # NOQA
        if not post:
            self.error(404)
            return
        self.render("post_view.html",
                    post=post,
                    comments=comments,
                    liked=liked)

    def post(self, post_id):
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()
        if self.request.get("like"):
            # If the user likes the post
            if post and self.user:
                post.likes += 1
                like = Like(post_id=int(post_id), author=self.user)
                like.put()
                post.put()
            self.redirect("/%s" % post_id)
        elif self.request.get("unlike"):
            # If the user unlikes the post
            if post and self.user:
                post.likes -= 1
                like = Like.gql("WHERE post_id=:1 AND author.username=:2", int(post_id), self.user.username).get()  # NOQA
                key = like.key
                key.delete()
                post.put()
            self.redirect("/%s" % post_id)
        else:
            # If the user comments on the post
            self.content = self.request.get("content")
            if self.content:
                comment = Comment(content=str(self.content),
                                  author=self.user,
                                  post_id=int(post_id))
                comment.put()
                self.redirect("/%s" % post_id)
            else:
                self.render("post_view.html", post=post)


class EditPost(BlogHandler):
    """Renders post_edit page and contains function to update the post"""
    def get(self):
        if self.user:
            self.post_id = self.request.get("post")
            key = ndb.Key('Post', int(self.post_id), parent=blog_key())
            post = key.get()
            if not post:
                self.error(404)
                return
            self.render("post_edit.html",
                        post=post,
                        subject=post.subject,
                        content=post.content)
        else:
            self.redirect("/login")

    def post(self):
        self.post_id = self.request.get("post")
        key = ndb.Key('Post', int(self.post_id), parent=blog_key())
        post = key.get()
        if post and post.author.username == self.user.username:
            self.subject = self.request.get("subject")
            self.content = self.request.get("content")
            if self.subject and self.content:
                post.subject = self.subject
                post.content = self.content
                post.put()
                self.redirect("/")
            else:
                error = "you need both a subject and content"
                self.render("post_edit.html",
                            post=post,
                            subject=self.subject,
                            content=self.content,
                            error=error)
        else:
            self.redirect("/")


class DeletePost(BlogHandler):
    """Renders post_delete page and contains function to delete page"""
    def get(self):
        if self.user:
            self.post_id = self.request.get("post")
            key = ndb.Key('Post', int(self.post_id), parent=blog_key())
            post = key.get()
            if not post:
                self.error(404)
                return
            self.render("post_delete.html", post=post)
        else:
            self.redirect("/login")

    def post(self):
        self.post_id = self.request.get("post")
        key = ndb.Key('Post', int(self.post_id), parent=blog_key())
        post = key.get()
        if post and post.author.username == self.user.username:
            key.delete()
        self.redirect("/")


class EditComment(BlogHandler):
    """Renders comment_edit page and function to update comment"""
    def get(self):
        if self.user:
            self.comment_id = self.request.get("comment")
            key = ndb.Key('Comment', int(self.comment_id))
            comment = key.get()
            if not comment:
                self.error(404)
                return
            self.render("comment_edit.html",
                        content=comment.content,
                        post_id=comment.post_id)
        else:
            self.redirect("/login")

    def post(self):
        self.comment_id = self.request.get("comment")
        key = ndb.Key('Comment', int(self.comment_id))
        comment = key.get()
        if comment and comment.author.username == self.user.username:
            content = self.request.get("content")
            if content:
                comment.content = content
                comment.put()
                self.redirect("/%s" % comment.post_id)
            else:
                error = "you need both a subject and content"
                self.render("comment_edit.html",
                            content=content,
                            post_id=comment.post_id,
                            error=error)
        else:
            self.redirect("/%s" % comment.post_id)


class DeleteComment(BlogHandler):
    """Renders comment_delete page and deltes the comment"""
    def get(self):
        if self.user:
            self.comment_id = self.request.get("comment")
            key = ndb.Key('Comment', int(self.comment_id))
            comment = key.get()
            if not comment:
                self.error(404)
                return
            self.render("comment_delete.html", comment=comment)
        else:
            self.redirect("/login")

    def post(self):
        self.comment_id = self.request.get("comment")
        key = ndb.Key('Comment', int(self.comment_id))
        comment = key.get()
        if comment and comment.author.username == self.user.username:
            post_id = comment.post_id
            key.delete()
        self.redirect("/%s" % post_id)


app = webapp2.WSGIApplication([('/', Main),
                               ('/signup', Signup),
                               ('/login', Login),
                               ('/newpost', NewPost),
                               ('/logout', Logout),
                               ('/welcome', Welcome),
                               ('/([0-9]+)', PostPage),
                               ('/comment/edit', EditComment),
                               ('/comment/delete', DeleteComment),
                               ('/edit', EditPost),
                               ('/delete', DeletePost)
                               ], debug=True)
