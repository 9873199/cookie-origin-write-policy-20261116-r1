"""Reviewer demonstration. Imports the unchanged frozen HTTPX product."""
import time
import httpx


def scenario(label, steps):
    print('\n'+label, flush=True)
    seen=[]
    def respond(request):
        step=steps[len(seen)]
        seen.append(request.headers.get('cookie',''))
        print('  '+str(request.url),flush=True)
        print('  sent Cookie: '+(seen[-1] or '(empty)'),flush=True)
        return httpx.Response(200,headers=[('set-cookie',x) for x in step[1]])
    policy=httpx.SecureCookiePolicy(is_public_suffix=lambda host:host in {'test','co.test'})
    with httpx.Client(transport=httpx.MockTransport(respond),cookie_policy=policy) as client:
        for url,headers in steps:
            client.get(url)
            time.sleep(.8)
    return seen[-1]


normal=scenario('Ordinary HTTP overwrite attempt',[
    ('https://app.site.test/private',['sid=good; Secure; Path=/private']),
    ('http://app.site.test/private',['sid=evil; Path=/private']),
    ('https://app.site.test/private/x',[])])
print('  secure value preserved:',normal=='sid=good',flush=True)

duplicate=scenario('Two Path attributes in one HTTP response cookie',[
    ('https://app.site.test/private',['sid=good; Secure; Path=/private']),
    ('http://app.site.test/private',['sid=evil; Path=/private; Path=/safe']),
    ('https://app.site.test/private/x',[])])
print('  secure value preserved:',duplicate=='sid=good',flush=True)

suffix=scenario('Two Domain attributes; inspect a sibling request',[
    ('https://attacker.co.test/',['foreign=bad; Domain=co.test; Domain=attacker.co.test; Path=/']),
    ('https://victim.co.test/',[])])
print('  sibling request contains foreign cookie:',bool(suffix),flush=True)
