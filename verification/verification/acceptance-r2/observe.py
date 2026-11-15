import json
import httpx

headers=['__Host-id=bad; Secure; Path=/private; Path=/',
         'foreign=bad; Domain=co.test; Domain=attacker.co.test; Path=/']
def reply(request):return httpx.Response(200,headers=[('set-cookie',x) for x in headers])
with httpx.Client(transport=httpx.MockTransport(reply),cookie_policy=httpx.SecureCookiePolicy(is_public_suffix=lambda d:d=='co.test')) as client:
    client.get('https://attacker.co.test/')
    rows=[{'name':c.name,'domain':c.domain,'path':c.path,'secure':c.secure} for c in client.cookies.jar]
    print(json.dumps(rows,indent=2))
    assert any(c['name']=='__Host-id' and c['path']=='/private' for c in rows)
    assert any(c['name']=='foreign' and c['domain']=='.co.test' for c in rows)
