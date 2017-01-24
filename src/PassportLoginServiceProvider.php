<?php namespace Fivelabs\PassportLogin;

use Illuminate\Routing\Router;
use Illuminate\Foundation\Support\Providers\RouteServiceProvider;

class PassportLoginServiceProvider extends RouteServiceProvider
{

    /**
     * @var string
     */
    protected $configName = 'passport_login';

    /**
     * Perform post-registration booting of services.
     *
     * @return void
     */
    public function boot()
    {
        parent::boot();

        $this->publishes([
            $this->getPackageConfigPath() => config_path("{$this->configName}.php"),
        ], 'config');
    }

    /**
     * Register bindings in the container.
     *
     * @return void
     */
    public function register()
    {
        parent::register();

        $this->mergeConfigFrom($this->getPackageConfigPath(), $this->configName);
    }

    /**
     * @return string
     */
    protected function getPackageConfigPath()
    {
        return __DIR__."/../config/{$this->configName}.php";
    }

    /**
     * Define the routes for the application.
     *
     * @param Router|\Illuminate\Routing\Router $router
     * @return void
     */
    public function map(Router $router)
    {
        $router->group([
            'namespace' => $this->namespace,
            'prefix' => 'oauth',
            'middleware' => ['cors'],
        ], function (Router $router) {

            $router->post('login', config('passport_login.login_method'));
            $router->post('logout/{tokenId}', config('passport_login.logout_method'))->middleware('api');

        });

    }

}