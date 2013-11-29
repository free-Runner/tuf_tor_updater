echo "* Generate metainfo file with writemetainfo.py."
echo "* python writemetainfo.py lw1378.privatekey lw1378.publickey"
echo "* Default directory is given, and just put all files we want to update into the directory"
cd /home/laiwang/Documents/repository_tool/
python writemetainfo.py lw1378.privatekey lw1378.publickey
echo "* Generate targets_files with repository_operator.py."
echo "* python repository_operator.py --generate_file_dir targets_files"
echo "* Copy all update files and metainfo file into targets_files dir"
echo "* When generating the repository, files into targets_files will be copied"
echo "  to the tuf targets directory."
python repository_operator.py --generate_file_dir targets_files
cd ./writemetainfo_dir/
cp -r * /home/laiwang/Documents/repository_tool/targets_files
echo "* Generate tuf repository with repository_operator.py."
echo "* python repository_operator.py --generate_repository targets_files"
cd /home/laiwang/Documents/repository_tool/
python repository_operator.py --update_repository targets_files
echo "* Update the metadata on server."
cd /home/laiwang/Documents/apache_Server/
rm -r *
cd /home/laiwang/Documents/repy_tuf/
#rm -r ./client/
cd /home/laiwang/Documents/repository_tool/path/to/repository/
cp -r * /home/laiwang/Documents/apache_Server/
#cd /home/laiwang/Documents/repository_tool/path/to/
#cp -r client/ /home/laiwang/Documents/repy_tuf/
#cd /home/laiwang/Documents/repy_tuf/
#echo "* Okay, we'll try to download the update on client side."
#echo "* python softwareupdater.py"
#python softwareupdater.py
cd /home/laiwang/Documents/repository_tool/
#echo "* remove all temp files."
rm -r ./targets_files/
#rm -r ./path/
echo "* process complete."
