from flask import Flask, render_template, redirect
import jinja2, traceback
from utils.logging import log_error
from utils.security import set_secret_key
from pages import mobile_api, admin, survey_designer

try:
    from utils.secure import ENCRYPTION_KEY
except ImportError as e:
    if e.message != "No module named secure":
        raise
    else:
        print "You have not provided a secure.py file."
        exit()

if len( ENCRYPTION_KEY ) != 32:
    print "Your key is not 32 characters. The key must be exactly 32 charcters long."
    exit()

def subdomain(directory):
    app = Flask(__name__, static_folder=directory + "/static")
    set_secret_key(app)
    loader = [app.jinja_loader, jinja2.FileSystemLoader(directory + "/templates")]
    app.jinja_loader = jinja2.ChoiceLoader(loader)
    return app

# Register pages here
app = subdomain("frontend")
app.register_blueprint(mobile_api.mobile_api)
app.register_blueprint(admin.admin)
app.register_blueprint(survey_designer.survey_designer)

@app.route("/<page>.html")
def strip_dot_html(page):
    #strips away the dot html from pages
    return redirect("/%s" % page)

# Points our custom 404 page (in /frontend/templates) to display on a 404 error.
# (note, function name is irrelevant, it is the
@app.errorhandler(404)
def e404(e):
    return render_template("404.html")

# Defines additional behavior for HTML 500 errors, in this case logs a stacktrace.
@app.errorhandler(500)
def e500_text(e):
    try:
        stacktrace = traceback.format_exc()
        print(stacktrace)
    except Exception as e:
        log_error(e)
    return render_template("500.html")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
