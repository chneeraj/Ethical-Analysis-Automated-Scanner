from flask import Flask

def create_app():
    app = Flask(__name__)
    
    # Make sure templates folder is correctly set
    app.template_folder = 'templates'  # This is the default, but ensure it's correct
    
    from .routes import main
    app.register_blueprint(main)
    
    return app