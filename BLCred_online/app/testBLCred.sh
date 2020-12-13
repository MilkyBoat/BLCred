
echo
echo " ____    __       _____                         _  "
echo "|  _ \  | |      /  ___|   _  __   ____     __ | | "
echo "| ___/  | |     |  /      | |/_/  / __ \   /  \! | "
echo "|  _ \  | |___  |  \___   |  /   | ____/  | () | | "
echo "|____/  |_____|  \_____|  |_|     \____    \__/|_| "
echo

cd javascript

if [ ! -d "./node_modules" ]; then
    npm install
fi

echo
echo "-----------------------"
echo "enrollAdmin ..."
echo
node enrollAdmin
echo
echo "-----------------------"
echo "registerUser ..."
echo
node registerUser

echo
echo "-----------------------"
echo "invoke ..."
echo
node invoke
