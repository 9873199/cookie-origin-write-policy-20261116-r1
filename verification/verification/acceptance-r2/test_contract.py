"""Prepared from requested cookie contracts; bind to final frozen API before use."""
import asyncio
import httpx
import pytest

def exchange(mode, steps, *, policy=True):
    sent=[];index=0
    def respond(request):
        nonlocal index
        step=steps[index];index+=1
        sent.append((str(request.url),request.headers.get('cookie','')))
        headers=[('set-cookie',x) for x in step.get('set',[])]
        if step.get('location'):headers.append(('location',step['location']))
        return httpx.Response(step.get('status',200),headers=headers)
    options={'transport':httpx.MockTransport(respond)}
    if policy:options['cookie_policy']=httpx.SecureCookiePolicy(is_public_suffix=lambda d:d in {'test','co.test'})
    if mode=='sync':
        with httpx.Client(**options) as client:
            for step in steps:
                client.get(step['url'],headers=step.get('headers',{}))
    else:
        async def execute():
            async with httpx.AsyncClient(**options) as client:
                for step in steps: await client.get(step['url'],headers=step.get('headers',{}))
        asyncio.run(execute())
    assert index==len(steps)
    return sent

@pytest.mark.parametrize('mode',['sync','async'])
@pytest.mark.parametrize('header,scheme,allowed',[
    ('__Secure-id=ok; Secure; Path=/','https',True),
    ('__Secure-id=bad; Path=/','https',False),
    ('__Secure-id=bad; Secure; Path=/','http',False),
    ('__Host-id=ok; Secure; Path=/','https',True),
    ('__Host-id=bad; Secure; Path=/; Domain=','https',False),
    ('__Host-id=bad; Secure; Path=/; Domain=site.test','https',False),
    ('__Host-id=bad; Secure; Path=/x','https',False),
    ('__Host-id=bad; Path=/','https',False),
])
def test_prefix_receiving_then_actual_sent_cookie(mode,header,scheme,allowed):
    result=exchange(mode,[{'url':scheme+'://site.test/','set':[header]},{'url':'https://site.test/'}])
    assert bool(result[-1][1]) is allowed

@pytest.mark.parametrize('mode',['sync','async'])
@pytest.mark.parametrize('attack_url,attack',[
    ('http://app.site.test/','sid=evil; Path=/'),
    ('http://app.site.test/private/x','sid=evil; Path=/private/x'),
    ('http://app.site.test/','sid=evil; Domain=site.test; Path=/'),
    ('http://app.site.test/','sid=gone; Path=/private; Max-Age=0'),
    ('http://app.site.test/','sid=gone; Domain=site.test; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT'),
    ('http://app.site.test/','sid=evil; Path=/private; Path=/safe'),
])
def test_insecure_overlap_cannot_write_or_delete_secure(mode,attack_url,attack):
    result=exchange(mode,[{'url':'https://app.site.test/private','set':['sid=good; Secure; Path=/private']},
        {'url':attack_url,'set':[attack]},{'url':'https://app.site.test/private/x'}])
    assert result[-1][1]=='sid=good'

@pytest.mark.parametrize('mode',['sync','async'])
def test_domain_label_boundary_and_public_suffix_rejected(mode):
    result=exchange(mode,[{'url':'https://notsite.test/','set':['foreign=bad; Domain=site.test; Path=/','suffix=bad; Domain=test; Path=/']},
        {'url':'https://notsite.test/'}])
    assert result[-1][1]==''

@pytest.mark.parametrize('mode',['sync','async'])
def test_https_update_and_expiry_still_work(mode):
    result=exchange(mode,[{'url':'https://site.test/','set':['sid=one; Secure; Path=/']},
        {'url':'https://site.test/','set':['sid=two; Secure; Path=/']},
        {'url':'https://site.test/','set':['sid=gone; Secure; Path=/; Max-Age=0']},
        {'url':'https://site.test/'}])
    assert result[1][1]=='sid=one' and result[2][1]=='sid=two' and result[3][1]==''

@pytest.mark.parametrize('mode',['sync','async'])
def test_forged_host_header_cannot_supply_security_origin(mode):
    result=exchange(mode,[{'url':'http://site.test/','headers':{'Host':'secure.site.test'},'set':['__Secure-id=bad; Secure; Path=/']},
        {'url':'https://site.test/'}])
    assert result[-1][1]==''

@pytest.mark.parametrize('mode',['sync','async'])
def test_actual_redirect_hops_are_checked(mode):
    sent=[]
    def respond(request):
        sent.append((str(request.url),request.headers.get('cookie','')))
        if request.url.path=='/start':return httpx.Response(302,headers=[('location','http://site.test/attack'),('set-cookie','sid=good; Secure; Path=/')])
        if request.url.path=='/attack':return httpx.Response(302,headers=[('location','https://site.test/final'),('set-cookie','sid=evil; Path=/')])
        return httpx.Response(200)
    options={'transport':httpx.MockTransport(respond),'follow_redirects':True,'cookie_policy':httpx.SecureCookiePolicy()}
    if mode=='sync':
        with httpx.Client(**options) as c: c.get('https://site.test/start')
    else:
        async def execute():
            async with httpx.AsyncClient(**options) as c: await c.get('https://site.test/start')
        asyncio.run(execute())
    assert len(sent)==3 and sent[1][1]=='' and sent[2][1]=='sid=good'

def test_policy_does_not_escape_to_default_client():
    strict=exchange('sync',[{'url':'https://site.test/','set':['__Secure-id=value; Path=/']},{'url':'https://site.test/'}])
    default=exchange('sync',[{'url':'https://site.test/','set':['__Secure-id=value; Path=/']},{'url':'https://site.test/'}],policy=False)
    assert strict[-1][1]=='' and default[-1][1]=='__Secure-id=value'

def test_explicit_manual_cookie_is_separate():
    captured=[]
    def respond(request):captured.append(request.headers.get('cookie',''));return httpx.Response(200)
    with httpx.Client(transport=httpx.MockTransport(respond),cookie_policy=httpx.SecureCookiePolicy()) as c:
        c.cookies.set('__Secure-manual','explicit',domain='site.test',path='/')
        c.get('https://site.test/')
    assert captured==['__Secure-manual=explicit']

@pytest.mark.parametrize('mode',['sync','async'])
def test_host_prefix_cannot_be_stored_at_non_root_via_duplicate_path(mode):
    result=exchange(mode,[{'url':'https://site.test/','set':['__Host-id=bad; Secure; Path=/private; Path=/']},
        {'url':'https://site.test/private'}])
    assert result[-1][1]==''

@pytest.mark.parametrize('mode',['sync','async'])
def test_public_suffix_cannot_be_hidden_by_second_domain_attribute(mode):
    result=exchange(mode,[{'url':'https://attacker.co.test/','set':['foreign=bad; Domain=co.test; Domain=attacker.co.test; Path=/']},
        {'url':'https://victim.co.test/'}])
    assert result[-1][1]==''
