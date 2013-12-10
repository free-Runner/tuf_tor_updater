SERVER_PATH="/var/www/"
REPO_PATH="./repo/"

echo "* Updating tuf repository with target files"
if [ $1 = "timestamp" ]
then
	python repository_operator2.py --refresh_timestamp $SERVER_PATH
	echo "python repository_operator2.py --refresh_timestamp "$SERVER_PATH
fi
if [ $1 = "release" ]
then
	python repository_operator2.py --refresh_release $SERVER_PATH
	echo "python repository_operator2.py --refresh_release "$SERVER_PATH
fi
if [ $1 = "targets" ]
then
	python repository_operator2.py --refresh_targets $SERVER_PATH
	echo "python repository_operator2.py --refresh_targets "$SERVER_PATH
fi
if [ $1 = "root" ]
	then
	python repository_operator2.py --refresh_root $SERVER_PATH
	echo "python repository_operator2.py --refresh_root "$SERVER_PATH
fi
echo "* Process complete."
