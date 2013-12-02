SERVER_PATH="/var/www/"
REPO_PATH="./repo/"
KEY_NAME="lw1378"

echo "* Generating metainfo file with writemetainfo.py"
#echo "* python writemetainfo.py lw1378.privatekey lw1378.publickey"
python writemetainfo.py $KEY_NAME".privatekey" $KEY_NAME".publickey" -n
echo "* Generating targets_files directory"
#echo "* python repository_operator.py --generate_file_dir targets_files"
python repository_operator2.py --generate_file_dir targets_files
echo "* Copying all files and metainfo file into targets_files dir"
cp -r ./writemetainfo_dir/* ./targets_files
echo "* Updating tuf repository with target files"
python repository_operator2.py --update_repository targets_files
#rm -rf ./targets_files
echo "* Uploading modified repository onto server"
cp -r  $REPO_PATH"repository/metadata" $SERVER_PATH
cp -r  $REPO_PATH"repository/targets" $SERVER_PATH
echo "* process complete."
