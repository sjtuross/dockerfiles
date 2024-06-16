#!/usr/local/bin/python3
#coding:  utf-8
__author__ = 'T3rry'
import re
from requests_toolbelt.multipart.encoder import MultipartEncoder
from Crypto.Util.number import bytes_to_long,long_to_bytes
from Crypto.Cipher  import  PKCS1_v1_5,AES
from Crypto.PublicKey import RSA
from Crypto import Random
from ecdsa  import ECDH, NIST224p, SigningKey
from binascii import a2b_hex, b2a_hex
import hashlib,base64,lz4.block,zlib
import sys,os,time,platform
import json,requests,random
import getopt,ctypes,codecs
import urllib
from flask import Flask, request, jsonify, redirect, abort
import requests
import json
from urllib.parse import urlparse, urlunparse, urljoin, quote, unquote

cookie_path = "115-cookie.txt"
cookie = open(cookie_path).read()

mode = '115'
class  Fake115Client(object):
        def  __init__(self,  cookie,user_agent):

                self.app_version='25.2.2'
                self.api_version  =  '2.0.1.7'
                self.cookie=cookie
                #                self.ua='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0'
                self.ua= user_agent
                self.content_type='application/x-www-form-urlencoded'
                self.header={"User-Agent"  :  self.ua,"Content-Type":  self.content_type,  "Cookie":self.cookie  }
                self.crc_salt= '^j>WD3Kr?J2gLFjD4W2y@'
                self.md5_salt = 'Qclm8MGWUv59TnrR0XPg'
                self.remote_pubkey  ='0457A29257CD2320E5D6D143322FA4BB8A3CF9D3CC623EF5EDAC62B7678A89C91A83BA800D6129F522D034C895DD2465243ADDC250953BEEBA'
                self.private_key  =  RSA.construct((0x8C81424BC166F4918756E9F7B22EFAA03479B081E61896872CB7C51C910D7EC1A4CE2871424D5C9149BD5E08A25959A19AD3C981E6512EFDAB2BB8DA3F1E315C294BD117A9FB9D8CE8E633B4962E087C629DC6CA3A149214B4091EF2B0363CB3AE6C7EE702377F055ED3CD93F6C342256A76554BBEA7F203437BBE65F2DA2741,  0x10001,  0x3704DAB00D80C25E464FFB785A16D95F688D0A5823811758C16308D5A1DB55FA800D967A9B4AEDE79AA783ADFFDCDB23541C80B8D436901F172B1CCCA190B224DBE777BF18B96DD9A30AACE8780350793A4F90A645A7747EF695622EADBE23A4C6D88F22E87842B43B35486C2D1B5B1FA77DB3528B0910CA84EDB7A46AFDBED1))
                self.public_key  =  RSA.construct((0x8686980c0f5a24c4b9d43020cd2c22703ff3f450756529058b1cf88f09b8602136477198a6e2683149659bd122c33592fdb5ad47944ad1ea4d36c6b172aad6338c3bb6ac6227502d010993ac967d1aef00f0c8e038de2e4d3bc2ec368af2e9f10a6f1eda4f7262f136420c07c331b871bf139f74f3010e3c4fe57df3afb71683,  0x10001))
                self.g_key_l = a2b_hex('7806AD4C33865D184C013F46')
                self.g_key_s = a2b_hex('2923215E')
                self.g_kts = a2b_hex('F0E569AEBFDCBF8A1A45E8BE7DA673B8DE8FE7C445DA86C49B648B146AB4F1AA3801359E26692C86006B4FA5363462A62A966818F24AFDBD6B978F4D8F8913B76C8E93ED0E0D483ED72F88D8FEFE7E8650954FD1EB832634DB667B9C7E9D7A8132EAB633DE3AA95934663BAABA816048B9D5819CF86C8477FF5478265FBEE81E369F34805C452C9B76D51B8FCCC3B8F5')
                self.curve  =  NIST224p
                self.m115_l_rnd_key=None
                self.m115_s_rnd_key=None
                self.local_private_key=None
                self.local_public_key=None
                self.aes_key=None
                self.aes_iv=None
                self.user_id=None
                self.user_key=None
                self.std_out_handle=None
                self.filecount=0
                self.cid=0

                sk  =SigningKey.generate(curve=self.curve)
                ecdh  =  ECDH(curve=self.curve)
                ecdh.load_private_key(sk)
                local_public_key = ecdh.get_public_key().to_string()

                self.local_public_key=b'\x29'+local_public_key
                ecdh.load_received_public_key_bytes(a2b_hex(self.remote_pubkey))
                secret  =  ecdh.generate_sharedsecret_bytes()
                self.aes_key=secret[0:16]
                self.aes_iv=secret[-16:]

                if  self.get_userkey()  is  False:
                        print('Get  userkey  info  failed!')

        def  m115_init(self):
            self.g_key_l = a2b_hex('7806AD4C33865D184C013F46')
            self.g_key_s = a2b_hex('2923215E')
                
        def  m115_setkey(self,randkey,sk_len):

                length=sk_len  *(sk_len-1)
                index=0
                xorkey=b''
                if  randkey:
                        for  i  in  range(0,sk_len):
                                x=(randkey[i]  +  self.g_kts[index])&0xff
                                xorkey += chr((self.g_kts[length]) ^ x).encode('latin1')
                                length  -=sk_len
                                index  +=sk_len

                if (sk_len == 4):
                        self.g_key_s=xorkey
                elif (sk_len == 12):
                    self.g_key_l = xorkey

        def  xor115_enc(self,src,key):
                header=''
                pad=  len(src)%4

                if  pad  >0:
                        for  i  in  range(0,pad):
                                header+=chr((src[i])^(key[i]))
                        src=src[pad:]
                lkey=len(key)
                secret=[]
                num=0
                for  s  in  src:
                        if  num>=lkey:
                                num=num%lkey
                        secret.append(  chr(  (s)^(key[num])  )  )
                        num+=1

                return  (header+"".join(secret))

        def    m115_encode(self,plaintext):
                self.m115_init()
                self.m115_l_rnd_key        =Random.new().read(16)
                self.m115_setkey(self.m115_l_rnd_key,4)
                tmp = self.xor115_enc(plaintext.encode('latin1'), self.g_key_s)[::-1]
                xortext = self.xor115_enc(tmp.encode('latin1'),  self.g_key_l).encode('latin1')
                cipher  =  PKCS1_v1_5.new(self.public_key)
                ciphertext  =  cipher.encrypt(self.m115_l_rnd_key+xortext)
                ciphertext = urllib.parse.quote(base64.b64encode(ciphertext))

                return  ciphertext

        def    m115_decode(self,ciphertext):
                key_size=16
                block_size=128
                plaintext=b''
                ciphertext=base64.b64decode(ciphertext)
                block=len(ciphertext)//block_size

                for  i  in  range(0,block):
                        m = long_to_bytes(pow(bytes_to_long(ciphertext[i*128:block_size]), self.public_key.e, self.public_key.n))
                        m=m[m.index(b'\x00')+1:]
                        plaintext += m
                        block_size += 128

                self.m115_s_rnd_key=plaintext[0:key_size]
                plaintext=plaintext[key_size:]
                self.m115_setkey(self.m115_l_rnd_key,4)
                self.m115_setkey(self.m115_s_rnd_key,12)
                tmp=  self.xor115_enc(plaintext,self.g_key_l)[::-1]
                plaintext=  self.xor115_enc(tmp.encode('latin1'),self.g_key_s)
                return  plaintext

        def  ec115_get_token(self,data):  #md5(fileid+filesize+preid+uid+timestap+md5(uid))
                m  =  hashlib.md5()
                m.update(data)
                return  m.hexdigest()

        def  ec115_compress_decode(self,data):
                size=ord(data[0])+(ord(data[1])<<8)
                return(lz4.block.decompress(data[2:size+2],0x2000))

        def  ec115_encode_data(self,data):
                mode  =  AES.MODE_ECB
                BS  =  AES.block_size
                pad  =lambda  s:  s  +(BS  -  len(s)%  BS)*  chr(0)
                unpad  =lambda  s  :  s[0:-ord(s[-1])]
                data=pad(data)
                cipher_text=''
                xor_key=self.aes_iv
                tmp=''

                cryptos  =  AES.new(self.aes_key,  mode)
                for  i  in  range(0,len(data)):
                        tmp+=chr(ord(data[i])^ord(xor_key[i%16]))
                        if((i%16)==15):
                                xor_key=cryptos.encrypt(tmp)
                                cipher_text  +=  xor_key
                                tmp=''

                return  cipher_text

        def  ec115_encode_token(self,timestap=None):
                r1=random.randint(0x0,0xff)
                r2=random.randint(0x0,0xff)
                tmp=''

                try:
                        for  i  in  range(0,15):
                                tmp+=chr(ord(self.local_public_key[i])^r1)
                        tmp+=chr(r1)+chr(0x73^r1)
                        timestap=hex(timestap)[2:].decode('hex')

                        for  i  in  range(0,3):
                                tmp+=chr(r1)
                        for  i  in  range(0,4):
                                tmp+=chr(r1^ord(timestap[3-i]))
                        for  i  in  range(15,30):
                                tmp+=chr(ord(self.local_public_key[i])^r2)
                        tmp+=chr(r2)+chr(1^r2)
                        for  x  in  range(0,3):
                                tmp+=chr(r2)

                        crc=  zlib.crc32(self.crc_salt+tmp)&  0xffffffff
                        h_crc32=  hex(crc)[2:]
                        if(len(h_crc32)%2  !=0):
                                h_crc32='0'+h_crc32
                        h_crc32=h_crc32.decode('hex')
                        for  i  in  range(0,4):
                                tmp+=(h_crc32[3-i])

                except  Exception  as  e:
                        print(e)

                return  base64.b64encode(tmp)

        def  ec115_decode(self,data):
                BS  =  AES.block_size
                pad  =lambda  s:  s  +(BS  -  len(s)%  BS)*  chr(0)
                unpad  =lambda  s  :  s[0:-ord(s[-1])]
                cipher  =  AES.new(self.aes_key,  AES.MODE_CBC,self.aes_iv)
                lz4_buff=cipher.decrypt((data[0:-(len(data)%16)]))

                return  self.ec115_compress_decode(lz4_buff)

        def  get_file_size(self,file):
                return  str(os.path.getsize(file))

        def  get_userkey(self):
                try:
                        r  =  requests.get("http://proapi.115.com/app/uploadinfo",headers=self.header)
                        resp=json.loads(r.content)
                        self.user_id=str(resp['user_id'])
                        self.user_key=str(resp['userkey']).upper()
                except  Exception  as  e:
                        print("Explired  cookie  !",e)
                        return  False

        def  show_folder_path(self):
                url='https://webapi.115.com/files?aid=1&cid='+self.cid+'&o=user_ptime&asc=0&offset=0&show_dir=1&limit=115&code=&scid=&snap=0&natsort=1&record_open_time=1&source=&format=json&type=&star=&is_q=&is_share='
                r  =  requests.get(url,headers=self.header)
                resp=json.loads(r.content)['path']
                path='{'
                for  f  in  resp:
                        path+=  f['name']+'=>'
                path=path[:-2]+'}'
                self.log(path,False,"PATH")

        def  get_preid(self,pickcode):

                file_url=self.get_download_url_by_pc(pickcode)

                token=self.cookie
                try:
                        token  =r.headers['Set-Cookie'].split(';')[0]
                except  Exception  as  e:
                        pass

                head  =  {  "User-Agent"  :  self.ua,"Range":"bytes=0-131071","Cookie":token}
                r2=  requests.get(file_url,headers=head)
                sha  =  hashlib.sha1()
                sha.update(r2.content)
                preid  =  sha.hexdigest()
                return  preid.upper()

        def  get_download_url_by_pc(self,pc):  
                url = "https://proapi.115.com/app/chrome/downurl"
                pc_data  =  ('{"pickcode":"%s"}')  %  ( pc)
                data='data='+self.m115_encode(pc_data)
                r  =  requests.post(url,  data=data,headers=self.header)
                ciphertext=(json.loads(r.content)['data'])
                plaintext=self.m115_decode(ciphertext)
                jtext=json.loads(plaintext).items()

                for  key,  value  in  jtext:
                        url  =value['url']['url']
                return  url

def get_file_id(file_path,cookie):
    encoded_path = urllib.parse.quote(file_path)

    url = f"https://webapi.115.com/files/getid?path={encoded_path}"
    headers = {
        'Host': 'webapi.115.com',
        'User-Agent': 'Mozilla/5.0 115Browser/23.9.3.2',
        'Cookie':cookie,
        'Accept-Encoding': 'gzip',
    }

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = json.loads(response.text)
        file_id = data.get('id')
        return file_id
    else:
        print(f"Error: {response.status_code}, {response.text}")
        return None

def get_files_info(file_id,cookie):
    url = f"https://webapi.115.com/files?aid=1&asc=0&cid={file_id}&fc_mix=0&format=json&limit=1000&o=user_ptime&offset=0&record_open_time=1&show_dir=1&snap=0"
    headers = {
        'Host': 'webapi.115.com',
        'User-Agent': 'Mozilla/5.0 115Browser/23.9.3.2',
        'Cookie':cookie,
        'Accept-Encoding': 'gzip',
    }

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: {response.status_code}, {response.text}")
        return None

def get_115url(path_param,cookie,user_agent):
    path, filename = os.path.split(path_param)
    file_id = get_file_id(path,cookie)

    if file_id:
        # 获取文件信息
        files_info = get_files_info(file_id,cookie)
        if files_info:
            matching_dicts = [d['pc'] for d in files_info['data'] if d.get('n') == filename]
            pc_value = matching_dicts[0]
            Download_url = Fake115Client(cookie,user_agent).get_download_url_by_pc(pc_value)
            return Download_url
    return False

app = Flask(__name__)

@app.route('/<path:path>', methods=['GET', 'POST'])
def index(path=''):
    current_url = request.url
    user_agent = request.headers.get('User-Agent')
    parsed_url = urlparse(current_url)
    path = unquote(parsed_url.path)
    try:
        download_url = get_115url(path,cookie,user_agent)
        print(download_url)
        if download_url:
            return redirect(download_url, code=302)
        else:
            abort(404)
    except:
        abort(404)

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5302, threaded=True)

