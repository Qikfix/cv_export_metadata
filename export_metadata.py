#!/usr/bin/env python3
"""
Application to generate the metadata when exporting data
from Satellite/Content View Version
"""

import json
import sys
import argparse

stage = []

try:
    import requests
except ImportError:
    print("Please install the python-requests module.")
    sys.exit(-1)


def get_json(location):
    """
    Performs a GET using the passed URL location
    """
    requests.packages.urllib3.disable_warnings()
    r = requests.get(
        location, auth=(USERNAME, PASSWORD), verify=SSL_VERIFY, timeout=10
    )
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
        headers=POST_HEADERS,
        timeout=30,
    )

    return result.json()


def return_product_label(repo_label, content_view_id):
    """
    Function to return the product label
    """
    # content_view_id = obj['content_view_id']
    repos = get_json(
        KATELLO_API
        + "/content_views/"
        + str(content_view_id)
        + "/repositories"
    )

    for prd in repos["results"]:
        if prd["label"] == repo_label:

            # To collect the correct info about the product
            product_id = prd["product"]["id"]
            product = get_json(KATELLO_API + "/products/" + str(product_id))

            return product["label"]


def return_content_info(repo_label, content_view_id):
    """
    Function to return the content info
    """
    stage = {}
    # content_view_id = obj['content_view_id']
    repos = get_json(
        KATELLO_API
        + "/content_views/"
        + str(content_view_id)
        + "/repositories"
    )

    for prd in repos["results"]:
        if prd["label"] == repo_label:
            aux = prd["relative_path"].split("/")[2:]
            url = "/" + "/".join(aux)
            stage.update({"id": prd["content_id"]})
            stage.update({"label": prd["content_label"]})
            stage.update({"url": url})

            return stage


def return_is_redhat_repo(repo_label, content_view_id):
    """
    Function to return if it's a redhat repo
    """

    # content_view_id = obj['content_view_id']
    repos = get_json(
        KATELLO_API
        + "/content_views/"
        + str(content_view_id)
        + "/repositories"
    )

    for prd in repos["results"]:
        if prd["label"] == repo_label:
            product_id = prd["product"]["id"]
            product = get_json(KATELLO_API + "/products/" + str(product_id))

            return product["redhat"]


def return_gpg_info(product):
    if product.get('gpg_key'):
        aux = {}
        aux.update({"name": product['gpg_key']['name']})
        stage.append(product['gpg_key']['name'])
    else:
        aux = {}
    
    return aux


def populate_gpg_info():
    # org_id = 1
    keys = get_json(
        KATELLO_API
        + "/content_credentials"
        + "?organization_id=" + str(ORG)
    )

    aux = {}
    final_list = list(set(stage))
    for label in final_list:
        for obj in keys['results']:
            if label == obj['name']:
                aux.update({label: {}})
                aux[label].update({"name": obj['name']})
                aux[label].update({"content_type": obj['content_type']})
                aux[label].update({"content": obj['content']})
    
    return aux


def main(args):
    """
    Main routine that creates or re-uses an organization and
    life cycle environments. If life cycle environments already
    exist, exit out.
    """

    global URL
    URL = "https://" + args.c
    # URL for the API to your deployed Satellite 6 server

    global SAT_API
    SAT_API = "%s/katello/api/v2/" % URL
    # Katello-specific API

    global KATELLO_API
    KATELLO_API = "%s/katello/api/" % URL

    global POST_HEADERS
    POST_HEADERS = {"content-type": "application/json"}
    # Default credentials to login to Satellite 6
    # USERNAME = "user_here"
    # PASSWORD = "password_here"

    global USERNAME
    USERNAME = args.u

    global PASSWORD
    PASSWORD = args.p
    # Ignore SSL for now

    global SSL_VERIFY
    SSL_VERIFY = False

    global ORG
    ORG = args.o

    cv = get_json(KATELLO_API + "/content_views")
    cvv = get_json(KATELLO_API + "/content_view_versions")

    # The Content View Version ID that you would like to create the metadata
    ccv_id = int(args.cvv_id)

    new_meta = {}
    new_meta.update(
        {"organization": cv["results"][0]["organization"]["label"]}
    )
    new_meta.update({"base_path": "/var/lib/pulp/exports"})
    new_meta.update({"repositories": {}})
    new_meta.update({"content_view": {}})
    new_meta.update({"content_view_version": {}})
    new_meta.update({"incremental": "false"})
    new_meta.update({"format": "syncable"})
    new_meta.update({"products": {}})
    new_meta.update({"gpg_keys": {}})

    for obj in cvv["results"]:
        if obj["id"] == ccv_id:
            # repositories
            for repo in obj["repositories"]:
                new_meta["repositories"].update({repo["label"]: {}})
                new_meta["repositories"][repo["label"]].update(
                    {"name": repo["name"], "label": repo["label"]}
                )

                # Some standard info
                new_meta["repositories"][repo["label"]].update(
                    {"description": None}
                )
                new_meta["repositories"][repo["label"]].update(
                    {"arch": "noarch"}
                )
                new_meta["repositories"][repo["label"]].update(
                    {"content_type": "yum"}
                )
                new_meta["repositories"][repo["label"]].update(
                    {"unprotected": "false"}
                )
                new_meta["repositories"][repo["label"]].update(
                    {"checksum_type": None}
                )
                new_meta["repositories"][repo["label"]].update(
                    {"os_versions": []}
                )
                new_meta["repositories"][repo["label"]].update({"major": None})
                new_meta["repositories"][repo["label"]].update({"minor": None})
                new_meta["repositories"][repo["label"]].update(
                    {"download_policy": "immediate"}
                )
                new_meta["repositories"][repo["label"]].update(
                    {"mirroring_policy": "mirror_complete"}
                )

                # Retrieving the product label
                product_label = return_product_label(
                    repo["label"], obj["content_view_id"]
                )

                new_meta["repositories"][repo["label"]].update(
                    {"product": {"label": product_label}}
                )
                new_meta["repositories"][repo["label"]].update({"gpg_key": {}})

                # Retrieving the content info
                content_info = return_content_info(
                    repo["label"], obj["content_view_id"]
                )
                new_meta["repositories"][repo["label"]].update(
                    {"content": content_info}
                )

                # Retrieving if the repo is or not redhat
                is_redhat_repo = return_is_redhat_repo(
                    repo["label"], obj["content_view_id"]
                )
                new_meta["repositories"][repo["label"]].update(
                    {"redhat": is_redhat_repo}
                )

                # For content_view
                new_meta["content_view"].update(
                    {"name": obj["content_view"]["name"]}
                )
                new_meta["content_view"].update(
                    {"label": obj["content_view"]["label"]}
                )
                new_meta["content_view"].update({"description": ""})
                new_meta["content_view"].update({"generated_for": "none"})

                # For content_view_version
                new_meta["content_view_version"].update(
                    {"major": obj["major"]}
                )
                new_meta["content_view_version"].update(
                    {"minor": obj["minor"]}
                )
                new_meta["content_view_version"].update({"description": ""})

                # For products
                content_view_id = obj["content_view_id"]
                repos = get_json(
                    KATELLO_API
                    + "/content_views/"
                    + str(content_view_id)
                    + "/repositories"
                )

                for prd in repos["results"]:
                    # To collect the correct info about the product
                    product_id = prd["product"]["id"]
                    product = get_json(
                        KATELLO_API + "/products/" + str(product_id)
                    )

                    # Creating the key for products
                    new_meta["products"].update({product["label"]: {}})
                    new_meta["products"][product["label"]].update(
                        {"name": product["name"]}
                    )

                    new_meta["products"][product["label"]].update(
                        {"label": product["label"]}
                    )
                    new_meta["products"][product["label"]].update(
                        {"description": product["description"]}
                    )
                    new_meta["products"][product["label"]].update(
                        {"cp_id": product["cp_id"]}
                    )

                    # Retrieving the gpg label and adding it, when around.
                    gpg_key_response = return_gpg_info(
                        product
                    )
                    new_meta["products"][product["label"]].update(
                        {"gpg_key": gpg_key_response}
                    )
                    new_meta["products"][product["label"]].update(
                        {"redhat": product["redhat"]}
                    )

    response = populate_gpg_info()
    new_meta["gpg_keys"].update(response)

    json_obj = json.dumps(new_meta, indent=4)
    with open("metadata.json", "w") as outfile:
        outfile.write(json_obj)


def menu():
    """
    Menu + args
    """
    parser = argparse.ArgumentParser(
        description="Generating the Content View Version Metadata."
    )
    parser.add_argument("-c", required=1, help="Satellite FQDN")
    parser.add_argument("-u", required=1, help="Username")
    parser.add_argument("-p", required=1, help="Password")
    parser.add_argument("-o", required=1, help="Satellite Organization ID")
    parser.add_argument("-cvv-id", required=1, help="Content View Version ID")
    args = parser.parse_args()

    main(args)


if __name__ == "__main__":
    menu()
