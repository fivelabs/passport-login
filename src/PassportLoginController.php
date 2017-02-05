<?php namespace Fivelabs\PassportLogin;

use App\User;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
use Illuminate\Foundation\Validation\ValidatesRequests;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

class PassportLoginController extends \Laravel\Passport\Http\Controllers\PersonalAccessTokenController
{

    use AuthenticatesUsers, ValidatesRequests;

    /**
     * Issue a personal access token after authenticating the users credentials once.
     *
     * @param Request $request
     * @return Response
     */
    public function login(Request $request)
    {
        $this->validateLogin($request);

        // If the class is using the ThrottlesLogins trait, we can automatically throttle
        // the login attempts for this application. We'll key this by the username and
        // the IP address of the client making these requests into this application.
        if ($this->hasTooManyLoginAttempts($request)) {
            $this->fireLockoutEvent($request);

            return $this->sendLockoutResponse($request);
        }

        if ($this->attemptLogin($request)) {
            return $this->sendLoginResponse($request);
        }

        // If the login attempt was unsuccessful we will increment the number of attempts
        // to login and redirect the user back to the login form. Of course, when this
        // user surpasses their maximum number of attempts they will get locked out.
        $this->incrementLoginAttempts($request);

        return $this->sendFailedLoginResponse($request);
    }

    /**
     * Get the failed login response instance.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    protected function sendFailedLoginResponse(Request $request)
    {
        return response('Unauthorized.', 401);
    }

    /**
     * Redirect the user after determining they are locked out.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    protected function sendLockoutResponse(Request $request)
    {
        $seconds = $this->limiter()->availableIn(
            $this->throttleKey($request)
        );

        $message = \Lang::get('auth.throttle', ['seconds' => $seconds]);

        return response($message, 401);
    }

    /**
     * Get the login username to be used by the controller.
     *
     * @return string
     */
    public function username()
    {
        return config('passport_login.username', 'email');
    }

    /**
     * Send the response after the user was authenticated.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    protected function sendLoginResponse(Request $request)
    {
        $this->clearLoginAttempts($request);

        return $this->authenticated($request, $this->guard()->user());
    }

    /**
     * The user has been authenticated.
     *
     * @param  Request  $request
     * @param  Authenticatable|User $user
     * @return mixed
     */
    protected function authenticated(Request $request, $user)
    {
        return $this->getTokenResponse($request, $user);
    }

    /**
     * Attempt to log the user into the application.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return bool
     */
    protected function attemptLogin(Request $request)
    {
        return $this->guard()->once(
            $this->credentials($request)
        );
    }

    /**
     * Validate the user login request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return void
     */
    protected function validateLogin(Request $request)
    {
        $rules = config('passport_login.rules', [
            $this->username() => 'required',
            'password' => 'required',
        ]);

        $this->validate($request, $rules);
    }

    /**
     * Delete the given token.
     *
     * @param  Request $request
     * @param  string $tokenId
     * @return Response
     */
    public function logout(Request $request, $tokenId)
    {
        return parent::destroy($request, $tokenId);
    }

    /**
     * @param Request $request
     * @return array|Response|User
     */
    public function user(Request $request)
    {
        return $this->getUserResponse($request, $this->guard()->user());
    }

    /**
     * @param Request $request
     * @param  Authenticatable|User $user
     * @return User
     */
    protected function getUserResponse(Request $request, $user) {
        return $user;
    }

    /**
     * Get the token name used to create the new token.
     *
     * @param Request $request
     * @param  Authenticatable|User $user
     * @return string
     */
    public function getTokenName(Request $request, $user)
    {
        return "User #{$user->id} - {$user->email} - {$request->ip()}";
    }

    /**
     * @param Request $request
     * @param  Authenticatable|User $user
     * @param array $scopes
     * @return array
     */
    protected function getTokenResponse(Request $request, $user, array $scopes = [])
    {
        $personalAccessTokenResult = $user->createToken($this->getTokenName($request, $user), $scopes);

        return [
            'accessToken' => $personalAccessTokenResult->accessToken,
            'accessTokenId' => $personalAccessTokenResult->token->id,
            'scopes' => $scopes,
        ];
    }

}