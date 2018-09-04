import logging
import json
from libs import baseview, util
from core.task import grained_permissions
from libs.serializers import UserINFO
from rest_framework.response import Response
from django.http import (HttpResponse, HttpResponseRedirect,
                         HttpResponseServerError)
from django.contrib.auth import authenticate
from django.db import transaction
from django.conf import settings
from rest_framework_jwt.settings import api_settings
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from onelogin.saml2.response import OneLogin_Saml2_Response

from core.models import (
    Account,
    Usermessage,
    Todolist,
    grained
)

CUSTOM_ERROR = logging.getLogger('Yearning.core.views')

jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
PERMISSION = {
    'ddl': '0',
    'ddlcon': [],
    'dml': '0',
    'dmlcon': [],
    'dic': '0',
    'diccon': [],
    'dicedit': '0',
    'user': '0',
    'base': '0',
    'dicexport': '0',
    'person': [],
    'query': '0',
    'querycon': ''
}


class userinfo(baseview.BaseView):
    '''
        User Management interface

        mothod：

        get:

            get all user information, a page consists of 20 user info

        put:

            if args equal to changepwd (/api/v1/userinfo/changepwd) change the password

            if args equal to changegroup (/api/v1/userinfo/changegroup) change the group

        post: 
   
            add user

        delete:
   
            del user
      
    '''

    def get(self, request, args=None):
        if args == 'all':
            try:
                page = request.GET.get('page')
            except KeyError as e:
                CUSTOM_ERROR.error(f'{e.__class__.__name__}: {e}')
                return HttpResponse(status=500)
            else:
                try:
                    page_number = Account.objects.count()
                    start = int(page) * 10 - 10
                    end = int(page) * 10
                    info = Account.objects.all()[start:end]
                    serializers = UserINFO(info, many=True)
                    return Response({'page': page_number, 'data': serializers.data})
                except Exception as e:
                    CUSTOM_ERROR.error(f'{e.__class__.__name__}: {e}')
                    return HttpResponse(e)

        elif args == 'permissions':
            user = request.GET.get('user')
            user = grained.objects.filter(username=user).first()
            return Response(user.permissions)

    def put(self, request, args=None):
        if args == 'changepwd':
            try:
                username = request.data['username']
                new_password = request.data['new']
            except KeyError as e:
                CUSTOM_ERROR.error(f'{e.__class__.__name__}: {e}')
                return HttpResponse(status=500)
            else:
                try:
                    user = Account.objects.get(username__exact=username)
                    user.set_password(new_password)
                    user.save()
                    return Response('%s--密码修改成功!' % username)
                except Exception as e:
                    CUSTOM_ERROR.error(f'{e.__class__.__name__}: {e}')
                    return HttpResponse(status=500)

        elif args == 'changegroup':
            try:
                username = request.data['username']
                group = request.data['group']
                department = request.data['department']
                permission = json.loads(request.data['permission'])
                brfore = Account.objects.filter(username=username).first()
            except KeyError as e:
                CUSTOM_ERROR.error(f'{e.__class__.__name__}: {e}')
                return HttpResponse(status=500)
            else:
                try:
                    if brfore.group == 'admin' and group == 'guest':
                        per = grained.objects.all().values('username', 'permissions')
                        for i in per:
                            for c in i['permissions']:
                                if isinstance(i['permissions'][c], list) and c == 'person':
                                    i['permissions'][c] = list(filter(lambda x: x != username, i['permissions'][c]))
                            grained.objects.filter(username=i['username']).update(permissions=i['permissions'])
                    grained.objects.filter(username=username).update(permissions=permission)
                    if group == 'admin' or group == 'perform':
                        Account.objects.filter(username=username).update(
                            group=group,
                            department=department,
                            is_staff=1
                        )
                    else:
                        Account.objects.filter(username=username).update(
                            group=group,
                            department=department,
                            is_staff=0
                        )
                    return Response('%s--权限修改成功!' % username)
                except Exception as e:
                    CUSTOM_ERROR.error(f'{e.__class__.__name__}: {e}')
                    return HttpResponse(status=500)

        elif args == 'changemail':
            try:
                username = request.data['username']
                mail = request.data['mail']
            except KeyError as e:
                CUSTOM_ERROR.error(f'{e.__class__.__name__}: {e}')
                return HttpResponse(status=500)
            else:
                try:
                    Account.objects.filter(username=username).update(email=mail)
                    return Response('%s--E-mail修改成功!' % username)
                except Exception as e:
                    CUSTOM_ERROR.error(f'{e.__class__.__name__}: {e}')
                    return HttpResponse(status=500)

    def post(self, request, args=None):
        try:
            username = request.data['username']
            password = request.data['password']
            group = request.data['group']
            department = request.data['department']
            email = request.data['email']
        except KeyError as e:
            CUSTOM_ERROR.error(f'{e.__class__.__name__}: {e}')
            return HttpResponse(status=500)
        else:
            try:
                if group == 'admin' or group == 'perform':
                    user = Account.objects.create_user(
                        username=username,
                        password=password,
                        department=department,
                        group=group,
                        is_staff=1,
                        email=email)
                    user.save()
                    grained.objects.get_or_create(username=username, permissions=PERMISSION)
                    return Response('%s 用户注册成功!' % username)
                elif group == 'guest':
                    user = Account.objects.create_user(
                        username=username,
                        password=password,
                        department=department,
                        group=group,
                        email=email
                    )
                    user.save()
                    grained.objects.get_or_create(username=username, permissions=PERMISSION)
                    return Response('%s 用户注册成功!' % username)
            except Exception as e:
                CUSTOM_ERROR.error(f'{e.__class__.__name__}: {e}')
                return Response(e)

    def delete(self, request, args=None):
        try:
            pr = Account.objects.filter(username=args).first()
            if pr.is_staff == 1:
                per = grained.objects.all().values('username', 'permissions')
                for i in per:
                    for c in i['permissions']:
                        if isinstance(i['permissions'][c], list) and c == 'person':
                            i['permissions'][c] = list(filter(lambda x: x != args, i['permissions'][c]))
                    grained.objects.filter(username=i['username']).update(permissions=i['permissions'])
            with transaction.atomic():
                Account.objects.filter(username=args).delete()
                Usermessage.objects.filter(to_user=args).delete()
                Todolist.objects.filter(username=args).delete()
                grained.objects.filter(username=args).delete()
            return Response('%s--用户已删除!' % args)
        except Exception as e:
            CUSTOM_ERROR.error(f'{e.__class__.__name__}: {e}')
            return HttpResponse(status=500)


class generaluser(baseview.BaseView):
    '''

    :argument 普通用户修改密码

    '''

    def post(self, request, args=None):
        if args == 'changepwd':
            try:
                username = request.data['username']
                old_password = request.data['old']
                new_password = request.data['new']
            except KeyError as e:
                CUSTOM_ERROR.error(f'{e.__class__.__name__}: {e}')
            else:
                try:
                    user = authenticate(username=username, password=old_password)
                    if user is not None and user.is_active:
                        user.set_password(new_password)
                        user.save()
                        return Response('%s--密码修改成功!' % username)
                    else:
                        return Response('%s--原密码不正确请重新输入' % username)
                except Exception as e:
                    CUSTOM_ERROR.error(f'{e.__class__.__name__}: {e}')
                    return HttpResponse(status=500)

    def put(self, request, args: str = None):
        try:
            mail = request.data['mail']
        except KeyError as e:
            CUSTOM_ERROR.error(f'{e.__class__.__name__}: {e}')
        else:
            try:
                Account.objects.filter(username=request.user).update(email=mail)
                return Response('邮箱地址已更新!')
            except Exception as e:
                CUSTOM_ERROR.error(f'{e.__class__.__name__}: {e}')
                return HttpResponse(status=500)


class authgroup(baseview.BaseView):
    '''

    认证组权限

    '''

    @grained_permissions
    def post(self, request, args=None):
        try:
            _type = request.data['permissions_type'] + 'edit'
            permission = grained.objects.filter(username=request.user).first()
            return Response(permission.permissions[_type])
        except Exception as e:
            CUSTOM_ERROR.error(f'{e.__class__.__name__}: {e}')
            return HttpResponse(status=500)


class ldapauth(baseview.AnyLogin):
    '''

    ldap用户认证

    '''

    def post(self, request, args: str = None):
        try:
            username = request.data['username']
            password = request.data['password']
        except KeyError as e:
            CUSTOM_ERROR.error(f'{e.__class__.__name__}: {e}')
        else:
            jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
            jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
            valite = util.auth(username=username, password=password)
            if valite:
                try:
                    user = Account.objects.filter(username=username).first()
                    user.set_password(password)
                    user.save()
                    payload = jwt_payload_handler(user)
                    token = jwt_encode_handler(payload)
                    return Response({'token': token, 'res': '', 'permissions': user.group})
                except:
                    permissions = Account.objects.create_user(
                        username=username,
                        password=password,
                        is_staff=0,
                        group='guest')
                    permissions.save()
                    grained.objects.get_or_create(username=username, permissions=PERMISSION)
                    _user = authenticate(username=username, password=password)
                    token = jwt_encode_handler(jwt_payload_handler(_user))
                    return Response({'token': token, 'res': '', 'permissions': 'guest'})
            else:
                return Response({'token': 'null', 'res': 'ldap账号认证失败,请检查ldap账号或ldap配置!'})

class samlauth(baseview.AnyLogin):
    '''

    saml用户认证

    '''
    def init_saml_auth(self, req):
        auth = OneLogin_Saml2_Auth(req, custom_base_path=settings.SAML_FOLDER)
        return auth


    def prepare_django_request(self, request):
        # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
        result = {
            'https': 'on' if request.is_secure() else 'off',
            'http_host': '192.168.2.12',
            'script_name': '/api/v1/samlauth?acs',
            'server_port': 80,
            'get_data': request.GET.copy(),
            # Uncomment if using ADFS as IdP, https://github.com/onelogin/python-saml/pull/144
            # 'lowercase_urlencoding': True,
            'post_data': request.POST.copy()
        }
        return result
    
    def post(self, request, args: str = None):
        req = self.prepare_django_request(request)
        auth = self.init_saml_auth(req)
        errors = []
        not_auth_warn = False
        success_slo = False
        attributes = False
        paint_logout = False
  
        if 'sso' in req['get_data']:
            res_url = auth.login()
            return Response({'token': 'null', 'res': res_url})
        elif 'sso2' in req['get_data']:
            return_to = OneLogin_Saml2_Utils.get_self_url(req) + reverse('attrs')
            token = jwt_encode_handler(jwt_payload_handler("permissions"))
            return Response({'token': token, 'res': '', 'permissions': user.group})
        elif 'slo' in req['get_data']:
            name_id = None
            session_index = None
            if 'samlNameId' in request.session:
                name_id = request.session['samlNameId']
            if 'samlSessionIndex' in request.session:
                session_index = request.session['samlSessionIndex']

            return HttpResponseRedirect(auth.logout(name_id=name_id, session_index=session_index))
        elif 'acs' in req['get_data']:
            auth.process_response()
            errors = auth.get_errors()
            not_auth_warn = not auth.is_authenticated()

            if not errors:
                #CUSTOM_ERROR.error(auth.get_attributes())
                #CUSTOM_ERROR.error(auth.get_nameid())
                
                if 'RelayState' in req['post_data'] and OneLogin_Saml2_Utils.get_self_url(req) != req['post_data']['RelayState']:

                    jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
                    jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
                    username=auth.get_nameid()

                    try:
                        user = Account.objects.filter(username=username).first()
                        payload = jwt_payload_handler(user)
                        token = jwt_encode_handler(payload)
                        #return Response({'token': token, 'res': '', 'permissions': user.group})
                    except:
                        permissions = Account.objects.create_user(
                            username=username,
                            password=username,
                            is_staff=0,
                            group='guest')
                        permissions.save()
                        grained.objects.get_or_create(username=username, permissions=PERMISSION)
                        user = authenticate(username=username, password=username)
                        token = jwt_encode_handler(jwt_payload_handler(user))
                    
                    response = HttpResponseRedirect('/#/login')
                    response.set_cookie('username', username ,3600)
                    response.set_cookie('password', username ,3600)
                    response.set_cookie('token', token ,3600)
                    response.set_cookie('permissions', user.group ,3600)
                    return response

                return HttpResponseRedirect('/#/login')
            return HttpResponseRedirect('/#/login')
        elif 'sls' in req['get_data']:
            dscb = lambda: request.session.flush()
            url = auth.process_slo(delete_session_cb=dscb)
            errors = auth.get_errors()
            if len(errors) == 0:
                if url is not None:
                    return HttpResponseRedirect(url)
                else:
                    success_slo = True

        if 'samlUserdata' in request.session:
            paint_logout = True
            if len(request.session['samlUserdata']) > 0:
                attributes = request.session['samlUserdata'].items()
        return HttpResponseRedirect(auth.login())

        #return Response({'token': 'null', 'res': 'saml账号认证失败,请检查账号或配置!' + json.dumps(req)})


class login_auth(baseview.AnyLogin):

    def post(self, request, args: str = None):

        '''
        普通登陆类型认证
        :return: jwt token
        '''

        try:
            user = request.data['username']
            password = request.data['password']
        except KeyError as e:
            CUSTOM_ERROR.error(f'{e.__class__.__name__}: {e}')
        else:
            permissions = authenticate(username=user, password=password)
            if permissions is not None and permissions.is_active:
                token = jwt_encode_handler(jwt_payload_handler(permissions))
                return Response({'token': token, 'res': '', 'permissions': permissions.group})
            else:
                return HttpResponse(status=400)
