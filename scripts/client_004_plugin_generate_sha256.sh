
echo "Generating SHA256 from the vault plugin"
export SHA256=$(shasum -a 256 /home/gopal.m/git/PRIVATE\ REPOSITORIES/hashicorp_vault_plugin/build_files/vault-cert-plugin | cut -d' ' -f1)
echo $SHA256

echo "Writing SHA256 to Plugin Catalog"
/data/SOFTWARES/hashicorpVault/vault write -address=http://127.0.0.1:5920 sys/plugins/catalog/secret/vault-cert-plugin sha_256="${SHA256}" command="vault-cert-plugin"

echo "Enabling the vault plugin"
/data/SOFTWARES/hashicorpVault/vault secrets enable -address=http://127.0.0.1:5920 -path=appviewx-pki -plugin-name=vault-cert-plugin plugin


