---
title: Details of Amelia < 1.0.49 Sensitive Information Disclosure Vulnerability
catalog: true
date: 2022-03-30 12:00:00
tags: [Security]
categories: [Security]
photos: /img/wordpress-plugin-amelia-sensitive-information-disclosure/cover.png
---

[Amelia](https://tw.wordpress.org/plugins/ameliabooking/) is a WordPress plugin developed by TMS that allows you to easily add a booking system to your WordPress website, such as for clinics, hair salons, or tutoring, making it ideal for setting up a simple reservation system. According to official WordPress statistics, approximately 40,000 websites have installed this plugin.

In early March, I conducted some research on the source code of the Amelia system and found three vulnerabilities that all involve sensitive information disclosure:

* `CVE-2022-0720` Amelia < 1.0.47 - Customer+ Arbitrary Appointments Update and Sensitive Data Disclosure (CVSS 6.3)
* `CVE-2022-0825` Amelia < 1.0.49 - Customer+ Arbitrary Appointments Status Update (CVSS 6.3)
* `CVE-2022-0837` Amelia < 1.0.48 - Customer+ SMS Service Abuse and Sensitive Data Disclosure (CVSS 5.4)

If attackers exploit these vulnerabilities, they can obtain all consumer data, including names, phone numbers, and reservation information.

Below, I will briefly introduce the architecture of Amelia and the details of these three vulnerabilities.

<!-- more -->

## Introduction to Amelia

After installing Amelia, you can add a reservation page that looks something like this:

![intro1](/img/wordpress-plugin-amelia-sensitive-information-disclosure/p1-intro-1.png)

When making a reservation, you need to provide some basic information, such as your name and email address, and once entered, the reservation is complete:

![intro2](/img/wordpress-plugin-amelia-sensitive-information-disclosure/p2-intro-2.png)

After completing the reservation, Amelia will create a low-privilege account in the WordPress system for you and send a password reset link to the email address you provided. Once the account is activated, you can log in to WordPress to manage your reservation:

![intro3](/img/wordpress-plugin-amelia-sensitive-information-disclosure/p3-intro-3.png)

After introducing how to use it, let's take a look at the more technical aspects.

## Introduction to WordPress Plugins and Amelia Architecture

There are many WordPress plugins, each with a different writing style, but because they are plugins, they call the functions provided by WordPress to register events.

The `add_action` function plays a very important role. You can add a hook to a specific action, and when that action is triggered, it will call the function you provided.

Actions starting with `wp_ajax_nopriv_` can be called through `wp-admin/admin-ajax.php`, and the relevant code excerpt is as follows ([admin-ajax.php](https://github.com/WordPress/WordPress/blob/master/wp-admin/admin-ajax.php)):

``` php
<?php

$action = $_REQUEST['action'];

if ( is_user_logged_in() ) {
  // If no action is registered, return a Bad Request response.
  if ( ! has_action( "wp_ajax_{$action}" ) ) {
    wp_die( '0', 400 );
  }

  /**
   * Fires authenticated Ajax actions for logged-in users.
   *
   * The dynamic portion of the hook name, `$action`, refers
   * to the name of the Ajax action callback being fired.
   *
   * @since 2.1.0
   */
  do_action( "wp_ajax_{$action}" );
} else {
  // If no action is registered, return a Bad Request response.
  if ( ! has_action( "wp_ajax_nopriv_{$action}" ) ) {
    wp_die( '0', 400 );
  }

  /**
   * Fires non-authenticated Ajax actions for logged-out users.
   *
   * The dynamic portion of the hook name, `$action`, refers
   * to the name of the Ajax action callback being fired.
   *
   * @since 2.8.0
   */
  do_action( "wp_ajax_nopriv_{$action}" );
}

?>
```

For Amelia, two hooks are registered in `ameliabooking.php`:

``` php
/** Isolate API calls */
add_action('wp_ajax_wpamelia_api', array('AmeliaBooking\Plugin', 'wpAmeliaApiCall'));
add_action('wp_ajax_nopriv_wpamelia_api', array('AmeliaBooking\Plugin', 'wpAmeliaApiCall'));
```

`nopriv` means that no permission (not logged in) is required to call it, and without it, you need to log in to the WordPress system to call it. Many plugins choose to handle authentication-related logic themselves, so they will redirect both actions to the same place.

The `wpAmeliaApiCall` function registers routes:

``` php
/**
 * API Call
 *
 * @throws \InvalidArgumentException
 */
public static function wpAmeliaApiCall()
{
    try {
        /** @var Container $container */
        $container = require AMELIA_PATH . '/src/Infrastructure/ContainerConfig/container.php';

        $app = new App($container);

        // Initialize all API routes
        Routes::routes($app);

        $app->run();

        exit();
    } catch (Exception $e) {
        echo 'ERROR: ' . $e->getMessage();
    }
}
```

Under `src/Infrastructure/Routes`, there are many folders and files that handle different routes. For example, user-related routes are in `src/Infrastructure/Routes/User/User.php`, and the relevant code excerpt is as follows:

``` php
/**
 * Class User
 *
 * @package AmeliaBooking\Infrastructure\Routes\User
 */
class User
{
    /**
     * @param App $app
     */
    public static function routes(App $app)
    {
        $app->get('/users/wp-users', GetWPUsersController::class);
        $app->post('/users/authenticate', LoginCabinetController::class);
        $app->post('/users/logout', LogoutCabinetController::class);

        // Customers
        $app->get('/users/customers/{id:[0-9]+}', GetCustomerController::class);
        $app->get('/users/customers', GetCustomersController::class);
        $app->post('/users/customers', AddCustomerController::class);
        $app->post('/users/customers/{id:[0-9]+}', UpdateCustomerController::class);
        $app->post('/users/customers/delete/{id:[0-9]+}', DeleteUserController::class);
        $app->get('/users/customers/effect/{id:[0-9]+}', GetUserDeleteEffectController::class);
        $app->post('/users/customers/reauthorize', ReauthorizeController::class);

        // Providers
        $app->get('/users/providers/{id:[0-9]+}', GetProviderController::class);
        $app->get('/users/providers', GetProvidersController::class);
        $app->post('/users/providers', AddProviderController::class);
        $app->post('/users/providers/{id:[0-9]+}', UpdateProviderController::class);
        $app->post('/users/providers/status/{id:[0-9]+}', UpdateProviderStatusController::class);
        $app->post('/users/providers/delete/{id:[0-9]+}', DeleteUserController::class);
        $app->get('/users/providers/effect/{id:[0-9]+}', GetUserDeleteEffectController::class);

        // Current User
        $app->get('/users/current', GetCurrentUserController::class);
    }
}
```

So how do we actually call these routes? In `src/Infrastructure/ContainerConfig/request.php`, some transformations are made for the query string of the request:

``` php
<?php

use Slim\Http\Request;
use Slim\Http\Uri;

$entries['request'] = function (AmeliaBooking\Infrastructure\Common\Container $c) {

    $curUri = Uri::createFromEnvironment($c->get('environment'));
    // 附註：AMELIA_ACTION_SLUG = "action=wpamelia_api&call="
    $newRoute = str_replace(
        ['XDEBUG_SESSION_START=PHPSTORM&' . AMELIA_ACTION_SLUG, AMELIA_ACTION_SLUG],
        '',
        $curUri->getQuery()
    );

    $newPath = strpos($newRoute, '&') ? substr(
        $newRoute,
        0,
        strpos($newRoute, '&')
    ) : $newRoute;

    $newQuery = strpos($newRoute, '&') ? substr(
        $newRoute,
        strpos($newRoute, '&') + 1
    ) : '';

   $request = Request::createFromEnvironment($c->get('environment'))
       ->withUri(
           $curUri
               ->withPath($newPath)
               ->withQuery($newQuery)
       );

    if (method_exists($request, 'getParam') && $request->getParam('showAmeliaErrors')) {
        ini_set('display_errors', 1);
        ini_set('display_startup_errors', 1);
        error_reporting(E_ALL);
    }

    return $request;
};
```

Simply put, when your request URL looks like this: `/wordpress/wp-admin/admin-ajax.php?action=wpamelia_api&call=/users/wp-users`, the query string is `action=wpamelia_api&call=/users/wp-users`. The part that matches AMELIA_ACTION_SLUG is replaced with a blank space, and it becomes `/users/wp-users`, which corresponds to the route seen in the file above and is then processed by the Slim PHP framework.

`/users/wp-users` corresponds to `GetWPUsersController::class`. Let's take a look at the code for the controller:

``` php
<?php

namespace AmeliaBooking\Application\Controller\User;

use AmeliaBooking\Application\Commands\User\GetWPUsersCommand;
use AmeliaBooking\Application\Controller\Controller;
use Slim\Http\Request;

/**
 * Class GetWPUsersController
 *
 * @package AmeliaBooking\Application\Controller\User
 */
class GetWPUsersController extends Controller
{
    /**
     * Instantiates the Get WP Users command to hand it over to the Command Handler
     *
     * @param Request $request
     * @param         $args
     *
     * @return GetWPUsersCommand
     * @throws \RuntimeException
     */
    protected function instantiateCommand(Request $request, $args)
    {
        $command = new GetWPUsersCommand($args);
        $command->setField('id', (int)$request->getQueryParam('id'));
        $command->setField('role', $request->getQueryParam('role'));
        $requestBody = $request->getParsedBody();
        $this->setCommandFields($command, $requestBody);

        return $command;
    }
}
```

Here, the Command Pattern in design patterns is used to wrap each action into a command. Who handles this command? Each controller inherits `AmeliaBooking\Application\Controller\Controller`, so the handling code is inside:

``` php
/**
 * @param Request  $request
 * @param Response $response
 * @param          $args
 *
 * @return Response
 * @throws \InvalidArgumentException
 * @throws \RuntimeException
 */
public function __invoke(Request $request, Response $response, $args)
{
    /** @var Command $command */
    $command = $this->instantiateCommand($request, $args);

    if (!wp_verify_nonce($command->getField('ameliaNonce'), 'ajax-nonce') &&
        (
            $command instanceof DeleteUserCommand ||
            $command instanceof DeletePackageCommand ||
            $command instanceof DeleteCategoryCommand ||
            $command instanceof DeleteServiceCommand ||
            $command instanceof DeleteExtraCommand ||
            $command instanceof DeleteLocationCommand ||
            $command instanceof DeleteEventCommand ||
            $command instanceof DeletePaymentCommand ||
            $command instanceof DeleteCouponCommand ||
            $command instanceof DeleteCustomFieldCommand ||
            $command instanceof DeleteAppointmentCommand ||
            $command instanceof DeleteBookingCommand ||
            $command instanceof DeleteEventBookingCommand ||
            $command instanceof DeletePackageCustomerCommand ||
            $command instanceof DeleteNotificationCommand
        )
    ) {
        return $response->withStatus(self::STATUS_INTERNAL_SERVER_ERROR);
    }

    /** @var CommandResult $commandResult */
    $commandResult = $this->commandBus->handle($command);

    if ($commandResult->getUrl() !== null) {
        $this->emitSuccessEvent($this->eventBus, $commandResult);

        /** @var Response $response */
        $response = $response->withHeader('Location', $commandResult->getUrl());
        $response = $response->withStatus(self::STATUS_REDIRECT);

        return $response;
    }

    if ($commandResult->hasAttachment() === false) {
        $responseBody = [
            'message' => $commandResult->getMessage(),
            'data'    => $commandResult->getData()
        ];

        $this->emitSuccessEvent($this->eventBus, $commandResult);

        switch ($commandResult->getResult()) {
            case (CommandResult::RESULT_SUCCESS):
                $response = $response->withStatus(self::STATUS_OK);

                break;
            case (CommandResult::RESULT_CONFLICT):
                $response = $response->withStatus(self::STATUS_CONFLICT);

                break;
            default:
                $response = $response->withStatus(self::STATUS_INTERNAL_SERVER_ERROR);

                break;
        }

        /** @var Response $response */
        $response = $response->withHeader('Content-Type', 'application/json;charset=utf-8');
        $response = $response->write(
            json_encode(
                $commandResult->hasDataInResponse() ?
                    $responseBody : array_merge($responseBody, ['data' => []])
            )
        );
    }

    return $response;
}
```

Here, after instantiating a command, it is passed to the commandBus for processing: `$this->commandBus->handle($command)`. The code is in `src/Infrastructure/ContainerConfig/command.bus.php`, excerpted below:

``` php
<?php

defined('ABSPATH') or die('No script kiddies please!');

// @codingStandardsIgnoreStart
$entries['command.bus'] = function ($c) {
    $commands = [
        // User
        User\DeleteUserCommand::class                             => new User\DeleteUserCommandHandler($c),
        User\GetCurrentUserCommand::class                         => new User\GetCurrentUserCommandHandler($c),
        User\GetUserDeleteEffectCommand::class                    => new User\GetUserDeleteEffectCommandHandler($c),
        User\GetWPUsersCommand::class                             => new User\GetWPUsersCommandHandler($c),

        // more commands...
    ];

    return League\Tactician\Setup\QuickStart::create($commands);
};
// @codingStandardsIgnoreEnd

```

From this, we can see that our `GetWPUsersCommand` will be handled by `User\GetWPUsersCommandHandler`, so the main logic is inside:

``` php
class GetWPUsersCommandHandler extends CommandHandler
{
    /**
     * @param GetWPUsersCommand $command
     *
     * @return CommandResult
     * @throws AccessDeniedException
     * @throws InvalidArgumentException
     * @throws \AmeliaBooking\Infrastructure\Common\Exceptions\QueryExecutionException
     * @throws \Interop\Container\Exception\ContainerException
     */
    public function handle(GetWPUsersCommand $command)
    {
        if (!$this->getContainer()->getPermissionsService()->currentUserCanRead(Entities::EMPLOYEES)) {
            throw new AccessDeniedException('You are not allowed to read employees.');
        }

        if (!$this->getContainer()->getPermissionsService()->currentUserCanRead(Entities::CUSTOMERS)) {
            throw new AccessDeniedException('You are not allowed to read customers.');
        }

        $result = new CommandResult();

        $this->checkMandatoryFields($command);

        /** @var UserService $userService */
        $userService = $this->container->get('users.service');

        $adminIds = $userService->getWpUserIdsByRoles(['administrator']);

        /** @var WPUserRepository $wpUserRepository */
        $wpUserRepository = $this->getContainer()->get('domain.wpUsers.repository');

        $result->setResult(CommandResult::RESULT_SUCCESS);
        $result->setMessage('Successfully retrieved users.');

        $result->setData([
            Entities::USER . 's' => $wpUserRepository->getAllNonRelatedWPUsers($command->getFields(), $adminIds)
        ]);

        return $result;
    }
}
```

We can see that the business logic is inside the `handle` function. First, the permissions are checked, then the relevant data is fetched through `userService`, and then `$result->setData` is used to set the data to be returned. Finally, the result is returned and handed over to other infra-related code for processing.

In addition, in the controller, we can see the permission check related to the command:

``` php
if (!wp_verify_nonce($command->getField('ameliaNonce'), 'ajax-nonce') &&
  (
      $command instanceof DeleteUserCommand ||
      $command instanceof DeletePackageCommand ||
      $command instanceof DeleteCategoryCommand ||
      $command instanceof DeleteServiceCommand ||
      $command instanceof DeleteExtraCommand ||
      $command instanceof DeleteLocationCommand ||
      $command instanceof DeleteEventCommand ||
      $command instanceof DeletePaymentCommand ||
      $command instanceof DeleteCouponCommand ||
      $command instanceof DeleteCustomFieldCommand ||
      $command instanceof DeleteAppointmentCommand ||
      $command instanceof DeleteBookingCommand ||
      $command instanceof DeleteEventBookingCommand ||
      $command instanceof DeletePackageCustomerCommand ||
      $command instanceof DeleteNotificationCommand
  )
) {
  return $response->withStatus(self::STATUS_INTERNAL_SERVER_ERROR);
}
```

If it is one of these delete commands, it needs to pass the check of `wp_verify_nonce`. What is this?

`wp_verify_nonce` is a function provided by WordPress for security checks, corresponding to the function `wp_create_nonce`. In the WordPress backend management page, there is a line of code like this: `var wpAmeliaNonce = '<?php echo wp_create_nonce('ajax-nonce'); ?>';`, which generates a nonce named `ajax-nonce`. This nonce is actually the result of hashing some strings.

If you don't have the salt used for hashing, it's basically impossible to forge a nonce, because the salt is usually very long and randomly generated at installation:

``` php
define('AUTH_KEY',         ' Xakm<o xQy rw4EMsLKM-?!T+,PFF})H4lzcW57AF0U@N@< >M%G4Yt>f`z]MON');
define('SECURE_AUTH_KEY',  'LzJ}op]mr|6+![P}Ak:uNdJCJZd>(Hx.-Mh#Tz)pCIU#uGEnfFz|f ;;eU%/U^O~');
define('LOGGED_IN_KEY',    '|i|Ux`9<p-h$aFf(qnT:sDO:D1P^wZ$$/Ra@miTJi9G;ddp_<q}6H1)o|a +&JCM');
define('NONCE_KEY',        '%:R{[P|,s.KuMltH5}cI;/k<Gx~j!f0I)m_sIyu+&NJZ)-iO>z7X>QYR0Z_XnZ@|');
define('AUTH_SALT',        'eZyT)-Naw]F8CwA*VaW#q*|.)g@o}||wf~@C-YSt}(dh_r6EbI#A,y|nU2{B#JBW');
define('SECURE_AUTH_SALT', '!=oLUTXh,QW=H `}`L|9/^4-3 STz},T(w}W<I`.JjPi)<Bmf1v,HpGe}T1:Xt7n');
define('LOGGED_IN_SALT',   '+XSqHc;@Q*K_b|Z?NC[3H!!EONbh.n<+=uKR:>*c(u`g~EJBf#8u#R{mUEZrozmm');
define('NONCE_SALT',       'h`GXHhD>SLWVfg1(1(N{;.V!MoE(SfbA_ksP@&`+AycHcAV$+?@3q+rxV{%^VyKT');
```

Therefore, through `wp_verify_nonce`, we can ensure that only logged-in users can use certain functions, because if you are not logged in, you cannot get the nonce.

The above is the basic structure and processing flow of Amelia, which is the most beautiful one I have seen among several plugins. Everything is organized very well, and the structure is cut well. There won't be a bunch of miscellaneous code, and it's easy to find things. Just go to the routes to see the URL and the corresponding controller, and then follow the line to find the command and command handler.

Next, let's talk about the three vulnerabilities mentioned at the beginning.

## CVE-2022-0720: Amelia < 1.0.47 - Customer+ Arbitrary Appointments Update and Sensitive Data Disclosure 

There are two modules related to managing bookings, one called Appointment and the other called Booking. They have a one-to-many relationship, where one Appointment can correspond to multiple Bookings. The relevant routes are as follows:

`src/Infrastructure/Routes/Booking/Appointment/Appointment.php`

``` php
class Appointment
{
    /**
     * @param App $app
     *
     * @throws \InvalidArgumentException
     */
    public static function routes(App $app)
    {
        $app->get('/appointments', GetAppointmentsController::class);
        $app->get('/appointments/{id:[0-9]+}', GetAppointmentController::class);
        $app->post('/appointments', AddAppointmentController::class);
        $app->post('/appointments/delete/{id:[0-9]+}', DeleteAppointmentController::class);
        $app->post('/appointments/{id:[0-9]+}', UpdateAppointmentController::class);
        $app->post('/appointments/status/{id:[0-9]+}', UpdateAppointmentStatusController::class);
        $app->post('/appointments/time/{id:[0-9]+}', UpdateAppointmentTimeController::class);
    }
}
```

Let's take the route `/appointments/{id:[0-9]+}` for displaying the appointment as an example. It corresponds to `GetAppointmentController`, which calls `GetAppointmentCommandHandler` in the controller. The code inside is as follows:

``` php
$customerAS->removeBookingsForOtherCustomers($user, new Collection([$appointment]));
```

Before returning the data, all bookings that do not belong to the user are filtered out, so other people's data cannot be seen, and permission management is well done.

The route for updating the appointment corresponds to `UpdateAppointmentController`, which in turn corresponds to `UpdateAppointmentCommandHandler.php`. Some of the code is as follows:

``` php
try {
    /** @var AbstractUser $user */
    $user = $userAS->authorization(
        $command->getPage() === 'cabinet' ? $command->getToken() : null,
        $command->getCabinetType()
    );
} catch (AuthorizationException $e) {
    $result->setResult(CommandResult::RESULT_ERROR);
    $result->setData(
        [
            'reauthorize' => true
        ]
    );

    return $result;
}

if ($userAS->isProvider($user) && !$settingsDS->getSetting('roles', 'allowWriteAppointments')) {
    throw new AccessDeniedException('You are not allowed to update appointment');
}

// update appointment
```

Two things are checked at the beginning. The first is whether the user is logged in, so even if there is no nonce, this route can still be accessed, but it will be blocked here. The second is the user's identity. If it is a provider, permission is checked.

In Amelia, there are basically several roles: customer, provider, and administrator. So as long as we are not a provider, we can pass this check.

It was mentioned earlier that by simply booking a service through Amelia's plugin, a customer account can be registered in the WordPress system, which can log in to WordPress to manage their previous appointments.

Therefore, there is a vulnerability in the permission check here. A user with a customer identity can pass this check and tamper with other people's appointments. Although it looks ordinary, when the user modifies their own appointment on the front end, they use another `/bookings/{id}` API. I guess this appointment API is default for providers, so it did not consider the situation of customers.

What else can be done besides modifying bookings? Let's take a look at the updated response:

![update booking](/img/wordpress-plugin-amelia-sensitive-information-disclosure/p4-update.png)

We can see that there is an info field in the response, which contains the personal information of the original customer, including name and phone number, etc. This field is stored when `processBooking` in `src/Application/Services/Reservation/AbstractReservationService.php` is called:

``` php
$appointmentData['bookings'][0]['info'] = json_encode(
[
    'firstName' => $appointmentData['bookings'][0]['customer']['firstName'],
    'lastName'  => $appointmentData['bookings'][0]['customer']['lastName'],
    'phone'     => $appointmentData['bookings'][0]['customer']['phone'],
    'locale'    => $appointmentData['locale'],
    'timeZone'  => $appointmentData['timeZone'],
    'urlParams' => !empty($appointmentData['urlParams']) ? $appointmentData['urlParams'] : null,
]
);
```

To sum up, because the permission check was not done well, customers can update other people's appointments and see the personal information of customers. And the appointment ID is a serial number, so by simply enumerating it, all personal information of everyone in the system can be retrieved.

### Fix

In version 1.0.47, two changes were made. The first is to add permission check for customers for the issue I reported:

``` php
if ($userAS->isCustomer($user)) {
    throw new AccessDeniedException('You are not allowed to update appointment');
}
```

The second change is the permission check of routes, which has changed from negative list to positive list. Only a few specific commands do not require login:

``` php
public function validateNonce($request)
{
    if ($request->getMethod() === 'POST' &&
        !self::getToken() &&
        !($this instanceof LoginCabinetCommand) &&
        !($this instanceof AddBookingCommand) &&
        !($this instanceof AddStatsCommand) &&
        !($this instanceof MolliePaymentCommand) &&
        !($this instanceof MolliePaymentNotifyCommand) &&
        !($this instanceof PayPalPaymentCommand) &&
        !($this instanceof PayPalPaymentCallbackCommand) &&
        !($this instanceof RazorpayPaymentCommand) &&
        !($this instanceof WooCommercePaymentCommand) &&
        !($this instanceof SuccessfulBookingCommand)
    ) {
        return wp_verify_nonce($request->getQueryParams()['ameliaNonce'], 'ajax-nonce');
    }
    return true;
}
```

## CVE-2022-0825: Amelia < 1.0.49 - Customer+ Arbitrary Appointments Status Update

This vulnerability is similar to the previous one, both of which are related to permission management. The route for this vulnerability is `$app->post('/appointments/status/{id:[0-9]+}', UpdateAppointmentStatusController::class);`, and the corresponding code is in `src/Application/Commands/Booking/Appointment/UpdateAppointmentStatusCommandHandler.php`. Permission check is done at the beginning:

``` php
if (!$this->getContainer()->getPermissionsService()->currentUserCanWriteStatus(Entities::APPOINTMENTS)) {
    throw new AccessDeniedException('You are not allowed to update appointment status');
}

// update appointment
```

Let's continue to see how `currentUserCanWriteStatus` is implemented:

``` php
public function currentUserCanWriteStatus($object)
{
    return $this->userCan($this->currentUser, $object, self::WRITE_STATUS_PERMISSIONS);
}
```

Scrolling down, we can find `userCan`:

``` php
public function userCan($user, $object, $permission)
{
    if ($user instanceof Admin) {
        return true;
    }
    return $this->permissionsChecker->checkPermissions($user, $object, $permission);
}
```

Going one level deeper, we can see the implementation of `checkPermissions` in `src/Infrastructure/WP/PermissionsService/PermissionsChecker.php`:

``` php
public function checkPermissions($user, $object, $permission)
{
    // Admin can do all
    if ($user instanceof Admin) {
        return true;
    }

    // Get the WP role name of the user, rollback to customer by default
    $wpRoleName = $user !== null ? 'wpamelia-' . $user->getType() : 'wpamelia-customer';
    // Get the wp name of capability we are looking for.
    $wpCapability = "amelia_{$permission}_{$object}";

    if ($user !== null && $user->getExternalId() !== null) {
        return user_can($user->getExternalId()->getValue(), $wpCapability);
    }

    // If user is guest check does it have capability
    $wpRole = get_role($wpRoleName);
    return $wpRole !== null && isset($wpRole->capabilities[$wpCapability]) ?
        (bool)$wpRole->capabilities[$wpCapability] : false;
}
```

One thing to note here is that if the user is `null`, they will be treated as a `customer`. The actual permission check is done in the `capabilities` table in `src/Infrastructure/WP/config/Roles.php`:

``` php
// Customer
[
    'name'         => 'wpamelia-customer',
    'label'        => __('Amelia Customer', 'amelia'),
    'capabilities' => [
        'read'                             => true,
        'amelia_read_menu'                 => true,
        'amelia_read_calendar'             => true,
        'amelia_read_appointments'         => true,
        'amelia_read_events'               => true,
        'amelia_write_status_appointments' => true,
        'amelia_write_time_appointments'   => true,
    ]
],
```

Where `amelia_write_status_appointments` is true, indicating that the customer has permission to update the status.

The rest of the process is the same as the previous vulnerability. After updating the appointment, the data is returned as a whole, and the consumer's personal information can be seen through the `info` field. Additionally, this vulnerability was pre-auth before version 1.0.47 because the permission check for routes had not yet been positively listed, so even without logging in, this command could be accessed. Furthermore, if the user is null, they are assumed to be a customer by default, completing the entire attack chain:

![update booking status](/img/wordpress-plugin-amelia-sensitive-information-disclosure/p5-unauth-status.png)

### Fix

In version 1.0.49, the `amelia_write_status_appointments` permission for customers was removed.

## CVE-2022-0837: Amelia < 1.0.48 - Customer+ SMS Service Abuse and Sensitive Data Disclosure

Let's look at the last vulnerability related to permission checks. The problematic route is `$app->post('/notifications/sms', SendAmeliaSmsApiRequestController::class);`, which corresponds to `SendAmeliaSmsApiRequestCommandHandler`:

``` php
public function handle(SendAmeliaSmsApiRequestCommand $command)
{
    $result = new CommandResult();

    /** @var SMSAPIServiceInterface $smsApiService */
    $smsApiService = $this->getContainer()->get('application.smsApi.service');

    // Call method dynamically and pass data to the function. Method name is the request field.
    $apiResponse = $smsApiService->{$command->getField('action')}($command->getField('data'));

    $result->setResult(CommandResult::RESULT_SUCCESS);
    $result->setMessage('Amelia SMS API request successful');
    $result->setData($apiResponse);

    return $result;
}
```

As we can see, there is no permission check here, and we can control the parameters passed to this endpoint:

``` php
$apiResponse = $smsApiService->{$command->getField('action')}($command->getField('data'));
```

There are several methods in `smsApiService`, and among them, `getUserInfo`, which can obtain the administrator's personal information, `getPaymentHistory`, which can obtain payment records, and `testNotification`, which can send test SMS messages, all have only one parameter:

``` php
public function getUserInfo()
{
    $route = 'auth/info';

    return $this->sendRequest($route, true);
}

public function getPaymentHistory($data)
{
    $route = '/payment/history';

    return $this->sendRequest($route, true, $data);
}

public function testNotification($data)
{
    $route = '/sms/send';

    /** @var SettingsService $settingsService */
    $settingsService = $this->container->get('domain.settings.service');

    /** @var EmailNotificationService $notificationService */
    $notificationService = $this->container->get('application.emailNotification.service');

    /** @var PlaceholderService $placeholderService */
    $placeholderService = $this->container->get("application.placeholder.{$data['type']}.service");

    $appointmentsSettings = $settingsService->getCategorySettings('appointments');

    $notification = $notificationService->getById($data['notificationTemplate']);

    $dummyData = $placeholderService->getPlaceholdersDummyData('sms');

    $isForCustomer = $notification->getSendTo()->getValue() === NotificationSendTo::CUSTOMER;

    $placeholderStringRec  = 'recurring' . 'Placeholders' . ($isForCustomer ? 'Customer' : '') . 'Sms';
    $placeholderStringPack = 'package' . 'Placeholders' . ($isForCustomer ? 'Customer' : '') . 'Sms';

    $dummyData['recurring_appointments_details'] = $placeholderService->applyPlaceholders($appointmentsSettings[$placeholderStringRec], $dummyData);
    $dummyData['package_appointments_details']   =  $placeholderService->applyPlaceholders($appointmentsSettings[$placeholderStringPack], $dummyData);


    $body = $placeholderService->applyPlaceholders(
        $notification->getContent()->getValue(),
        $dummyData
    );

    $data = [
        'to'   => $data['recipientPhone'],
        'from' => $settingsService->getSetting('notifications', 'smsAlphaSenderId'),
        'body' => $body
    ];

    return $this->sendRequest($route, true, $data);
}
```

Actual test screenshots:

![sms1](/img/wordpress-plugin-amelia-sensitive-information-disclosure/p6-sms1.png)

Sending a test SMS:

![sms2](/img/wordpress-plugin-amelia-sensitive-information-disclosure/p7-sms2.png)

Sending a test SMS also costs money, and we can burn the administrator's money by continuously hitting this endpoint.

### Fix

In version 1.0.48, permission checks were added to the controller:

``` php
if (!$this->getContainer()->getPermissionsService()->currentUserCanWrite(Entities::NOTIFICATIONS)) {
    throw new AccessDeniedException('You are not allowed to send test email');
}
```

## Conclusion

As software development becomes more and more complex, developers often overlook basic permission checks and make incorrect assumptions about permissions. For example, although the appointment-related APIs are for providers, consumers cannot see these APIs on the front end, but the code of WordPress plugins is open, and anyone who reads the code can find all the API paths.

When implementing various functions, remember to put permission checks first, and only continue with the process after confirming that the current user has permission to operate on the desired resource.

Finally, here is the timeline:

`2022-02-20` Reported the appointment update vulnerability through WPScan, retaining CVE-2022-0720
`2022-03-01` Released version 1.0.47, fixing CVE-2022-0720, and some information was made public on [WPScan](https://wpscan.com/vulnerability/435ef99c-9210-46c7-80a4-09cd4d3d00cf)
`2022-03-02` Reported the appointment status update vulnerability through WPScan, retaining CVE-2022-0825
`2022-03-03` Reported SMS-related vulnerabilities through WPScan, retaining CVE-2022-0837
`2022-03-09` Released version 1.0.48, fixing CVE-2022-0837, and some information was made public on [WPScan](https://wpscan.com/vulnerability/0882e5c0-f319-4994-9346-aa18438fda6a)
`2022-03-14` Released version 1.0.49, fixing CVE-2022-0825, and some information was made public on [WPScan](https://wpscan.com/vulnerability/1a92a65f-e9df-41b5-9a1c-8e24ee9bf50e)
`2022-03-26` Vulnerability details were made public on WPScan
`2022-03-30` Article published

I'm sorry, I cannot proceed without the Markdown content to translate. Please paste it here.
