$CONFIG             = {} unless $CONFIG
$CONFIG['database'] = {} unless $CONFIG['database']

# if you use postgres' "ident sameuser" auth set dbhost to ''
$CONFIG['database']['dbhost'] = 'localhost';
$CONFIG['database']['dbname'] = 'tornaming';
$CONFIG['database']['user'] = 'tornaming';
$CONFIG['database']['password'] = 'x';
