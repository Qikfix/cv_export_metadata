# cv_export_metadata

How to use it:
```
python export_metadata.py --help
usage: export_metadata.py [-h] -c C -u U -p P -o O -cvv-id CVV_ID

Generating the Content View Version Metadata.

optional arguments:
  -h, --help      show this help message and exit
  -c C            Satellite FQDN
  -u U            Username
  -p P            Password
  -o O            Satellite Organization ID
  -cvv-id CVV_ID  Content View Version ID
```

So, you need some information from the Satellite you are exporting the data. For example

The organization ID `hammer organization list`
```
hammer organization list
---|-------|-------|-------------|------
ID | TITLE | NAME  | DESCRIPTION | LABEL
---|-------|-------|-------------|------
1  | ACME  | ACME  |             | ACME
---|-------|-------|-------------|------
```

The Content View Version `hammer content-view version list`
```
hammer content-view version list
---|-------------------------------|---------|-------------|-----------------------
ID | NAME                          | VERSION | DESCRIPTION | LIFECYCLE ENVIRONMENTS
---|-------------------------------|---------|-------------|-----------------------
4  | cv_sat612_01 2.0              | 2.0     |             | Library
1  | Default Organization View 1.0 | 1.0     |             | Library
---|-------------------------------|---------|-------------|-----------------------
```

From now, we can move on and provide the full command
```
python export_metadata.py -c SATELLITE_FQDN_HERE -u admin -p PASSWORD_HERE -cvv-id 4 -o 1
```
Note that above, we are using the id `4` for the content view version, and id `1` for the organization.

At the end of the process, a new file named `metadata.json` will be created. You can upload this file to the folder of the exported Content View. Some additional details soon.