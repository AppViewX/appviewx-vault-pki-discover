#/data/SOFTWARES/hashicorpVault/vault write pki-1/roles/example-dot-com allowed_domains=my-website.com allow_subdomains=true max_ttl=72h
#/data/SOFTWARES/hashicorpVault/vault write pki-2/roles/example-dot-com allowed_domains=my-website.com allow_subdomains=true max_ttl=72h
#/data/SOFTWARES/hashicorpVault/vault write pki-3/roles/example-dot-com allowed_domains=my-website.com allow_subdomains=true max_ttl=72h
#/data/SOFTWARES/hashicorpVault/vault write pki-4/roles/example-dot-com allowed_domains=my-website.com allow_subdomains=true max_ttl=72h
#/data/SOFTWARES/hashicorpVault/vault write pki-5/roles/example-dot-com allowed_domains=my-website.com allow_subdomains=true max_ttl=72h
#/data/SOFTWARES/hashicorpVault/vault write pki-6/roles/example-dot-com allowed_domains=my-website.com allow_subdomains=true max_ttl=72h
#/data/SOFTWARES/hashicorpVault/vault write pki-7/roles/example-dot-com allowed_domains=my-website.com allow_subdomains=true max_ttl=72h
#/data/SOFTWARES/hashicorpVault/vault write pki-8/roles/example-dot-com allowed_domains=my-website.com allow_subdomains=true max_ttl=72h
#/data/SOFTWARES/hashicorpVault/vault write pki-9/roles/example-dot-com allowed_domains=my-website.com allow_subdomains=true max_ttl=72h
#/data/SOFTWARES/hashicorpVault/vault write pki-10/roles/example-dot-com allowed_domains=my-website.com allow_subdomains=true max_ttl=72h


for i in {1..10}
do
	/data/SOFTWARES/hashicorpVault/vault write pki-$i/roles/example-dot-com allowed_domains=my-website.com allow_subdomains=true max_ttl=72h
done
