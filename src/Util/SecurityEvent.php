<?php

namespace MLukman\SecurityHelperBundle\Util;

enum SecurityEvent: string
{
    case LOGIN = 'LOGIN';
    case LOGOUT = 'LOGOUT';
    case LOGIN_FAILURE = 'LOGIN_FAILURE';
    case REGISTER = 'REGISTER';
    case RESET_PASSWORD_EMAIL = 'RESET_PASSWORD_EMAIL';
    case RESET_PASSWORD_SUCCESS = 'RESET_PASSWORD_SUCCESS';
    case RESET_PASSWORD_FAILURE = 'RESET_PASSWORD_FAILURE';
}
