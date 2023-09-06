from django.contrib import messages
from django.http.request import HttpRequest
from django.shortcuts import redirect, render
from django.urls import resolve, reverse
from django.views.decorators.http import require_GET, require_POST

from authentication import admin_authentication
from constants.common_constants import RUNNING_TESTS
from constants.message_strings import (MFA_CODE_6_DIGITS, MFA_CODE_DIGITS_ONLY, MFA_CODE_MISSING,
    MFA_CODE_WRONG)
from database.user_models_researcher import Researcher
from libs.security import verify_mfa
from libs.sentry import make_error_sentry, SentryTypes


@require_GET
def login_page(request: HttpRequest):
    if admin_authentication.check_is_logged_in(request):
        return redirect("/choose_study")
    
    return render(request, 'admin_login.html')


@require_POST
def validate_login(request: HttpRequest):
    """ Authenticates administrator login, redirects to login page if authentication fails. """
    username = request.POST.get("username", None)
    password = request.POST.get("password", None)
    mfa_code = request.POST.get("mfa_code", "")
    
    # Test password, username, if the don't match return to login page.
    if not (username and password and Researcher.check_password(username, password)):
        messages.warning(request, "Incorrect username & password combination; try again.")
        return redirect(reverse("login_pages.login_page"))
    
    # login has succeeded, researcher is safe to get
    researcher = Researcher.objects.get(username=username)
    
    # case: mfa is not required, but was provided
    if not researcher.mfa_token and mfa_code:
        messages.warning(request, "MFA code was not required.")
    
    # cases: mfa was missing, bad length, non-digits. Display message, only mfa missing requires
    # a return to the login page, other cases are guaranteed to fail mfa check.
    if researcher.mfa_token and mfa_code and len(mfa_code) != 6:
        messages.warning(request, MFA_CODE_6_DIGITS)
    if researcher.mfa_token and mfa_code and not mfa_code.isdecimal():
        messages.warning(request, MFA_CODE_DIGITS_ONLY)
    if researcher.mfa_token and not mfa_code:
        messages.error(request, MFA_CODE_MISSING)
        return redirect(reverse("login_pages.login_page"))
    
    # case: mfa is required, was provided, but was incorrect.
    if researcher.mfa_token and mfa_code and not verify_mfa(researcher.mfa_token, mfa_code):
        messages.error(request, MFA_CODE_WRONG)
        return redirect(reverse("login_pages.login_page"))
    
    # case: mfa is required, was provided, and was correct.
    # The redirect happens even when credentials need to be updated, any further levels of
    # redirection occur after the browser follows the redirect and hits the logic in
    # admin_authentication.py.
    admin_authentication.log_in_researcher(request, username)
    
    # Now we try to redirect the researcher to the appropriate page.
    from urls import LOGIN_REDIRECT_SAFE  # circular import
    
    redirect_page = researcher.most_recent_page
    try:
        resolve(redirect_page)  # check that the url we have is valid
    except Exception:
        redirect_page = ""
        if not RUNNING_TESTS:
            with make_error_sentry(SentryTypes.elastic_beanstalk):
                raise
    
    # test that its a valid url we can redirect to
    do_redirect = False
    matchable_redirect_page = redirect_page.lstrip("/")
    for url_pattern in LOGIN_REDIRECT_SAFE:
        if url_pattern.pattern.match(matchable_redirect_page):
            do_redirect = True
            break
    
    # the default is the the choose study page, which will itself redirect to a specific study
    # page if there is only a single study for this participant
    if not do_redirect:
        return redirect("/choose_study")
    return redirect(redirect_page)
