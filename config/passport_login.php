<?php

return [

    'login' => 'Fivelabs\PassportLogin\PassportLoginController@login',

    'logout' => 'Fivelabs\PassportLogin\PassportLoginController@logout',

    'user' => 'Fivelabs\PassportLogin\PassportLoginController@user',

    'username' => 'email',

    'rules' => [
        'email' => 'required',
        'password' => 'required',
    ],

];