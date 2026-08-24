<?php

declare(strict_types=1);

namespace PDS\WP2FA\Http;

final class AccessiblePageRenderer implements PageRenderer
{
    public function __construct(
        private readonly UrlGenerator $urls,
        private readonly NonceFieldProvider $nonces,
    ) {
    }

    /** @param array<string, mixed> $view */
    public function render(string $route, array $view, AuthenticationSnapshot $authentication): string
    {
        $title = match ($route) {
            Route::CHALLENGE => 'Complete two-factor authentication',
            Route::ENROLL => 'Set up two-factor authentication',
            Route::RECOVERY => 'Use a recovery code',
            default => 'Two-factor authentication',
        };
        $message = isset($view['message']) && is_string($view['message']) ? $view['message'] : '';
        $error = isset($view['error']) && is_string($view['error']) ? $view['error'] : '';
        $action = $this->actionFor($route, $view);
        $form = '';

        if ($action !== null) {
            $nonce = $this->nonces->field($action);
            $form = '<form method="post" action="' . $this->escape($this->urls->adminPost($action)) . '">'
                . $nonce
                . '<input type="hidden" name="pds_return_to" value="' . $this->escape((string) ($view['return_to'] ?? '')) . '">';

            if (($view['management'] ?? false) === true) {
                $form .= '<label for="pds-2fa-password">Current password</label>'
                    . '<input id="pds-2fa-password" name="password" type="password" autocomplete="current-password">';
            } elseif ($route === Route::CHALLENGE) {
                $form .= '<label for="pds-2fa-proof">Verification code</label>'
                    . '<input id="pds-2fa-proof" name="proof" inputmode="numeric" autocomplete="one-time-code" aria-describedby="pds-2fa-error">';
            } elseif ($route === Route::RECOVERY) {
                $form .= '<label for="pds-2fa-proof">Recovery code</label>'
                    . '<input id="pds-2fa-proof" name="proof" autocomplete="off" aria-describedby="pds-2fa-error">';
            } else {
                $form .= '<label for="pds-2fa-provider">Authentication method</label>'
                    . '<select id="pds-2fa-provider" name="provider"><option value="totp">Authenticator app</option><option value="webauthn">Security key</option></select>';
            }

            if (isset($view['interaction_reference']) && is_string($view['interaction_reference'])) {
                $form .= '<input type="hidden" name="interaction_reference" value="' . $this->escape($view['interaction_reference']) . '">';
            }
            $form .= '<button type="submit">Continue</button></form>';
        }

        $continue = '';
        if (isset($view['continue_url']) && is_string($view['continue_url'])) {
            $continue = '<p><a href="' . $this->escape($view['continue_url']) . '">Continue to verification</a></p>';
        }
        $recovery = '';
        if (isset($view['recovery_codes']) && is_array($view['recovery_codes'])) {
            $items = '';
            foreach ($view['recovery_codes'] as $code) {
                if (is_string($code)) {
                    $items .= '<li><code>' . $this->escape($code) . '</code></li>';
                }
            }
            $recovery = '<section><h2>Recovery codes</h2><p>Save these codes. They will only be shown once.</p><ul>' . $items . '</ul></section>';
        }

        $notice = $message !== '' ? '<p role="status">' . $this->escape($message) . '</p>' : '';
        $errorMarkup = $error !== ''
            ? '<div id="pds-2fa-error" role="alert"><p>' . $this->escape($error) . '</p></div>'
            : '<div id="pds-2fa-error" aria-live="polite"></div>';

        return '<!doctype html><html><head><meta charset="UTF-8"><title>' . $this->escape($title)
            . '</title></head><body><main><h1>' . $this->escape($title) . '</h1>'
            . $notice . $errorMarkup . $recovery . $form . $continue
            . '</main></body></html>';
    }

    /** @param array<string, mixed> $view */
    private function actionFor(string $route, array $view): ?string
    {
        if (($view['completed'] ?? false) === true) {
            return null;
        }
        if (($view['management'] ?? false) === true) {
            return Route::RECOVERY_REGENERATE_ACTION;
        }

        return match ($route) {
            Route::CHALLENGE => Route::CHALLENGE_ACTION,
            Route::RECOVERY => Route::RECOVERY_ACTION,
            Route::ENROLL => Route::ENROLLMENT_BEGIN_ACTION,
            default => null,
        };
    }

    private function escape(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}
