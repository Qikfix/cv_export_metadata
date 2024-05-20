#!/usr/bin/python

import json
import sys

try:
    import requests
except ImportError:
    print ("Please install the python-requests module.")
    sys.exit(-1)

# URL to your Satellite 6 server
# URL = "https://satellite.example.com"

# URL for the API to your deployed Satellite 6 server
SAT_API = "%s/katello/api/v2/" % URL
# Katello-specific API
KATELLO_API = "%s/katello/api/" % URL
POST_HEADERS = {'content-type': 'application/json'}
# Default credentials to login to Satellite 6
USERNAME = "admin"
PASSWORD = "password_here"
# Ignore SSL for now
SSL_VERIFY = False

# Name of the organization to be either created or used
ORG_NAME = "MyOrg"
# Name for life cycle environments to be either created or used
ENVIRONMENTS = ["Development", "Testing", "Production"]


def get_json(location):
    """
    Performs a GET using the passed URL location
    """

    r = requests.get(location, auth=(USERNAME, PASSWORD), verify=SSL_VERIFY)

    return r.json()


def post_json(location, json_data):
    """
    Performs a POST and passes the data to the URL location
    """

    result = requests.post(
        location,
        data=json_data,
        auth=(USERNAME, PASSWORD),
        verify=SSL_VERIFY,
        headers=POST_HEADERS)

    return result.json()


def return_product_label(repo_label, content_view_id):
    # content_view_id = obj['content_view_id']
    repos = get_json(KATELLO_API + "/content_views/" + str(content_view_id) + "/repositories")

    for prd in repos['results']:
        if prd['label'] == repo_label:

            # To collect the correct info about the product
            product_id = prd['product']['id']
            product = get_json(KATELLO_API + "/products/" + str(product_id))

            return product['label']


def return_content_info(repo_label, content_view_id):
    stage = {}
    # content_view_id = obj['content_view_id']
    repos = get_json(KATELLO_API + "/content_views/" + str(content_view_id) + "/repositories")

    for prd in repos['results']:
        if prd['label'] == repo_label:
            aux = prd['relative_path'].split("/")[2:]
            url = "/" + '/'.join(aux)
            stage.update({ "id": prd['content_id'] })
            stage.update({ "label": prd['content_label'] })
            stage.update({ "url": url })

            return stage


def return_is_redhat_repo(repo_label, content_view_id):
    # content_view_id = obj['content_view_id']
    repos = get_json(KATELLO_API + "/content_views/" + str(content_view_id) + "/repositories")

    for prd in repos['results']:
        if prd['label'] == repo_label:
            pass
            product_id = prd['product']['id']
            product = get_json(KATELLO_API + "/products/" + str(product_id))
            
            return product['redhat']


def main():
    """
    Main routine that creates or re-uses an organization and
    life cycle environments. If life cycle environments already
    exist, exit out.
    """

    cv = get_json(KATELLO_API + "/content_views")
    cvv = get_json(KATELLO_API + "/content_view_versions")

    ccv_id = 4

    new_meta = {}
    new_meta.update({ "organization": cv['results'][0]['organization']['label'] })
    new_meta.update({ "base_path": "/var/lib/pulp/exports" })
    new_meta.update({ "repositories": {} })
    new_meta.update({ "content_view": {} })
    new_meta.update({ "content_view_version": {} })
    new_meta.update({ "incremental": 'false' })
    new_meta.update({ "format": "syncable" })
    new_meta.update({ "products": {} })
    new_meta.update({ "gpg_keys": {} })

    for obj in cvv['results']:
        if obj['id'] == ccv_id:
            print("we got it")
            # repositories
            for repo in obj['repositories']:
                new_meta['repositories'].update({ repo['label']:{} })
                new_meta['repositories'][repo['label']].update({ "name": repo['name'], "label": repo['label'] })

                # Some standard info
                new_meta['repositories'][repo['label']].update({ "description": None })
                new_meta['repositories'][repo['label']].update({ "arch": "noarch" })
                new_meta['repositories'][repo['label']].update({ "content_type": "yum" })
                new_meta['repositories'][repo['label']].update({ "unprotected": "false" })
                new_meta['repositories'][repo['label']].update({ "checksum_type": None })
                new_meta['repositories'][repo['label']].update({ "os_versions": [] })
                new_meta['repositories'][repo['label']].update({ "major": None })
                new_meta['repositories'][repo['label']].update({ "minor": None })
                new_meta['repositories'][repo['label']].update({ "download_policy": "immediate" })
                new_meta['repositories'][repo['label']].update({ "mirroring_policy": "mirror_complete" })

                # Retrieving the product label
                product_label = return_product_label(repo['label'], obj['content_view_id'])

                new_meta['repositories'][repo['label']].update({ "product": {"label": product_label } })
                new_meta['repositories'][repo['label']].update({ "gpg_key": {} })

                # Retrieving the content info
                content_info = return_content_info(repo['label'], obj['content_view_id'])
                new_meta['repositories'][repo['label']].update({ "content": content_info })

                # Retrieving if the repo is or not redhat
                is_redhat_repo = return_is_redhat_repo(repo['label'], obj['content_view_id'])
                new_meta['repositories'][repo['label']].update({ "redhat": is_redhat_repo })

                # For content_view
                new_meta['content_view'].update({ "name": obj['content_view']['name'] })
                new_meta['content_view'].update({ "label": obj['content_view']['label'] })
                new_meta['content_view'].update({ "description": "" })
                new_meta['content_view'].update({ "generated_for": "none" })

                # For content_view_version
                new_meta['content_view_version'].update({ "major": obj['major'] })
                new_meta['content_view_version'].update({ "minor": obj['minor'] })
                new_meta['content_view_version'].update({ "description": "" })

                # For products
                content_view_id = obj['content_view_id']
                repos = get_json(KATELLO_API + "/content_views/" + str(content_view_id) + "/repositories")



                for prd in repos['results']:
                    # To collect the correct info about the product
                    product_id = prd['product']['id']
                    product = get_json(KATELLO_API + "/products/" + str(product_id))

                    # Creating the key for products
                    new_meta['products'].update({ product['label']:{} })
                    new_meta['products'][product['label']].update({ "name": product['name'] })

                    new_meta['products'][product['label']].update({ "label": product['label'] })
                    new_meta['products'][product['label']].update({ "description": product['description'] })
                    new_meta['products'][product['label']].update({ "cp_id": product['cp_id'] })
                    new_meta['products'][product['label']].update({ "gpg_key": {} })
                    new_meta['products'][product['label']].update({ "redhat": product['redhat'] })
    


                print("here")




    json_obj = json.dumps(new_meta, indent=4)
    with open("new_meta.json", "w") as outfile:
        outfile.write(json_obj)

    print("here")


if __name__ == "__main__":
    main()