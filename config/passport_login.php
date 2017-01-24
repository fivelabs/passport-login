<?php

return [

    'login_method' => 'Fivelabs\PassportLogin\PassportLoginController@login',

    'logout_method' => 'Fivelabs\PassportLogin\PassportLoginController@logout',

    'username' => 'email',

    'rules' => [
        'email' => 'required',
        'password' => 'required',
    ],

];