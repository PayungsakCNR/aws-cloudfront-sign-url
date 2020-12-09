from M2Crypto import EVP
import base64
import time

def aws_url_base64_encode(msg):
    msg_base64 = base64.b64encode(msg)
    msg_base64 = msg_base64.replace('+', '-')
    msg_base64 = msg_base64.replace('=', '_')
    msg_base64 = msg_base64.replace('/', '~')
    return msg_base64

def sign_string(message, priv_key_string):
    key = EVP.load_key_string(priv_key_string)
    key.reset_context(md='sha1')
    key.sign_init()
    key.sign_update(message)
    signature = key.sign_final()
    return signature

def create_url(url, encoded_signature, key_pair_id, expires):
    signed_url = "%(url)s?Expires=%(expires)s&Signature=%(encoded_signature)s&Key-Pair-Id=%(key_pair_id)s" % {
            'url':url,
            'expires':expires,
            'encoded_signature':encoded_signature,
            'key_pair_id':key_pair_id,
            }
    return signed_url

def get_canned_policy_url(url, priv_key_string, key_pair_id, expires):
    canned_policy = '{"Statement":[{"Resource":"%(url)s","Condition":{"DateLessThan":{"AWS:EpochTime":%(expires)s}}}]}' % {'url':url, 'expires':expires}

    signature = sign_string(canned_policy, priv_key_string)
    encoded_signature = aws_url_base64_encode(signature)

    signed_url = create_url(url, encoded_signature, key_pair_id, expires);

    return signed_url

def encode_query_param(resource):
    enc = resource
    enc = enc.replace('?', '%3F')
    enc = enc.replace('=', '%3D')
    enc = enc.replace('&', '%26')
    return enc


key_pair_id = "K30HN51FS31V5U" #from the AWS accounts CloudFront tab
priv_key_file = "private_key.pem" #your private keypair file
resource = "https://media.paocloud.co.th/Universe2020_Wallpaper_Desktop_Main.png"
expires = int(time.time()) + 300 #5 min

#Create the signed URL
priv_key_string = open(priv_key_file).read()
signed_url = get_canned_policy_url(resource, priv_key_string, key_pair_id, expires)

print(signed_url)

