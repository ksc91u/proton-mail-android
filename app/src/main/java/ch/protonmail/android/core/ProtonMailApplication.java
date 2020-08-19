/*
 * Copyright (c) 2020 Proton Technologies AG
 * 
 * This file is part of ProtonMail.
 * 
 * ProtonMail is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * ProtonMail is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with ProtonMail. If not, see https://www.gnu.org/licenses/.
 */
package ch.protonmail.android.core;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Application;
import android.app.NotificationManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.os.AsyncTask;
import android.os.Build;
import android.os.SystemClock;
import android.preference.PreferenceManager;
import android.text.SpannableString;
import android.text.TextUtils;
import android.text.util.Linkify;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.birbit.android.jobqueue.JobManager;
import com.datatheorem.android.trustkit.TrustKit;
import com.google.android.gms.common.GoogleApiAvailability;
import com.google.android.gms.common.GooglePlayServicesNotAvailableException;
import com.google.android.gms.common.GooglePlayServicesRepairableException;
import com.google.android.gms.security.ProviderInstaller;
import com.google.android.material.snackbar.Snackbar;
import com.squareup.otto.Bus;
import com.squareup.otto.Produce;
import com.squareup.otto.Subscribe;

import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;
import javax.inject.Singleton;

import ch.protonmail.android.BuildConfig;
import ch.protonmail.android.R;
import ch.protonmail.android.activities.BaseActivity;
import ch.protonmail.android.activities.guest.LoginActivity;
import ch.protonmail.android.api.AccountManager;
import ch.protonmail.android.api.NetworkConfigurator;
import ch.protonmail.android.api.NetworkSwitcher;
import ch.protonmail.android.api.ProtonMailApiManager;
import ch.protonmail.android.api.TokenManager;
import ch.protonmail.android.api.models.AllCurrencyPlans;
import ch.protonmail.android.api.models.Keys;
import ch.protonmail.android.api.models.Organization;
import ch.protonmail.android.api.models.PaymentMethod;
import ch.protonmail.android.api.models.User;
import ch.protonmail.android.api.models.doh.Proxies;
import ch.protonmail.android.api.models.room.contacts.ContactsDatabase;
import ch.protonmail.android.api.models.room.contacts.ContactsDatabaseFactory;
import ch.protonmail.android.api.models.room.messages.Message;
import ch.protonmail.android.api.models.room.messages.MessagesDatabase;
import ch.protonmail.android.api.models.room.messages.MessagesDatabaseFactory;
import ch.protonmail.android.api.models.room.sendingFailedNotifications.SendingFailedNotification;
import ch.protonmail.android.api.segments.event.AlarmReceiver;
import ch.protonmail.android.api.segments.event.EventManager;
import ch.protonmail.android.api.services.MessagesService;
import ch.protonmail.android.core.di.AppComponent;
import ch.protonmail.android.core.di.AppModule;
import ch.protonmail.android.core.di.DaggerAppComponent;
import ch.protonmail.android.events.ApiOfflineEvent;
import ch.protonmail.android.events.DownloadedAttachmentEvent;
import ch.protonmail.android.events.DraftCreatedEvent;
import ch.protonmail.android.events.ForceUpgradeEvent;
import ch.protonmail.android.events.InvalidAccessTokenEvent;
import ch.protonmail.android.events.Login2FAEvent;
import ch.protonmail.android.events.LoginEvent;
import ch.protonmail.android.events.LoginInfoEvent;
import ch.protonmail.android.events.MailboxLoginEvent;
import ch.protonmail.android.events.PasswordChangeEvent;
import ch.protonmail.android.events.RequestTimeoutEvent;
import ch.protonmail.android.events.Status;
import ch.protonmail.android.events.StorageLimitEvent;
import ch.protonmail.android.events.general.AvailableDomainsEvent;
import ch.protonmail.android.events.organizations.OrganizationEvent;
import ch.protonmail.android.events.payment.GetPaymentMethodsEvent;
import ch.protonmail.android.exceptions.ErrorStateGeneratorsKt;
import ch.protonmail.android.gcm.GcmUtil;
import ch.protonmail.android.jobs.FetchContactsDataJob;
import ch.protonmail.android.jobs.FetchContactsEmailsJob;
import ch.protonmail.android.jobs.FetchLabelsJob;
import ch.protonmail.android.jobs.organizations.GetOrganizationJob;
import ch.protonmail.android.jobs.user.FetchUserSettingsJob;
import ch.protonmail.android.prefs.SecureSharedPreferences;
import ch.protonmail.android.servers.notification.INotificationServer;
import ch.protonmail.android.servers.notification.NotificationServer;
import ch.protonmail.android.utils.AppUtil;
import ch.protonmail.android.utils.CustomLocale;
import ch.protonmail.android.utils.DownloadUtils;
import ch.protonmail.android.utils.FileUtils;
import ch.protonmail.android.utils.UiUtil;
import ch.protonmail.android.utils.crypto.OpenPGP;
import ch.protonmail.android.utils.extensions.TextExtensions;
import dagger.android.AndroidInjector;
import dagger.android.DispatchingAndroidInjector;
import dagger.android.HasActivityInjector;
import io.sentry.Sentry;
import io.sentry.android.AndroidSentryClientFactory;
import studio.forface.viewstatestore.ViewStateStoreConfig;
import timber.log.Timber;

import static ch.protonmail.android.api.segments.event.EventManagerKt.PREF_LATEST_EVENT;
import static ch.protonmail.android.core.Constants.Prefs.PREF_TIME_AND_DATE_CHANGED;
import static ch.protonmail.android.core.UserManagerKt.LOGIN_STATE_TO_INBOX;
import static ch.protonmail.android.core.UserManagerKt.PREF_LOGIN_STATE;
import static ch.protonmail.android.core.UserManagerKt.PREF_SHOW_STORAGE_LIMIT_REACHED;
import static ch.protonmail.android.core.UserManagerKt.PREF_SHOW_STORAGE_LIMIT_WARNING;

@Singleton
public class ProtonMailApplication extends Application implements HasActivityInjector {

    private static ProtonMailApplication sInstance;

    @Inject
    UserManager mUserManager;
    @Inject
    EventManager eventManager;
    @Inject
    JobManager jobManager;
    @Inject
    QueueNetworkUtil mNetworkUtil;
    @Inject
    ProtonMailApiManager mApi;
    @Inject
    OpenPGP mOpenPGP;
    @Inject
    DispatchingAndroidInjector<Activity> activityInjector;

    @Inject
    NetworkConfigurator networkConfigurator;
    @Inject
    NetworkSwitcher networkSwitcher;

    private Bus mBus;
    private boolean mIsInitialized;
    private boolean appInBackground;
    private AppComponent mAppComponent;
    private Snackbar apiOfflineSnackBar;
    @Nullable
    private StorageLimitEvent mLastStorageLimitEvent;
    private DraftCreatedEvent mLastDraftCreatedEvent;
    private WeakReference<Activity> mCurrentActivity;
    private boolean mUpdateOccurred;
    private AllCurrencyPlans mAllCurrencyPlans;
    private List<PaymentMethod> mPaymentMethods;
    private Organization mOrganization;
    private List<String> mAvailableDomains;
    private String mCurrentLocale;
    private boolean mChangedSystemTimeDate;
    private AlertDialog forceUpgradeDialog;

    private ContactsDatabase contactsDatabase;
    private MessagesDatabase messagesDatabase;

    private String API_URL = "";

    @NonNull
    public static ProtonMailApplication getApplication() {
        return sInstance;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        appInBackground = true;
        sInstance = this;
        mBus = new Bus();
        mBus.register(this);

        if (BuildConfig.DEBUG) {
            Timber.plant(new Timber.DebugTree());
        } else {
//            Sentry.init(
//                    String.format(
//                            getString(R.string.sentry_url),
//                            BuildConfig.SENTRY_DNS_1,
//                            BuildConfig.SENTRY_DNS_2
//                    ), new AndroidSentryClientFactory(this));
//            Timber.plant(new SentryTree());
        }

        // Try to upgrade TLS Provider if needed
        if (Constants.FeatureFlags.TLS_12_UPGRADE) {
            upgradeTlsProviderIfNeeded();
        }

        // Initialize TrustKit for TLS Certificate Pinning
        TrustKit.initializeWithNetworkSecurityConfiguration(this);
        mAppComponent = DaggerAppComponent.builder().appModule(new AppModule(ProtonMailApplication.this)).build();

        mAppComponent.inject(ProtonMailApplication.this);

        ViewStateStoreConfig.INSTANCE
                .setErrorStateGenerator(ErrorStateGeneratorsKt.getErrorStateGenerator());

        contactsDatabase = ContactsDatabaseFactory.Companion.getInstance(getApplicationContext()).getDatabase();
        messagesDatabase = MessagesDatabaseFactory.Companion.getInstance(getApplicationContext()).getDatabase();

        checkForUpdateAndClearCache();
        initLongRunningTask();
        FileUtils.createDownloadsDir(this);
        setupNotificationChannels();
    }

    private void upgradeTlsProviderIfNeeded() {
        try {
            ProviderInstaller.installIfNeeded(this);
        } catch (GooglePlayServicesRepairableException e) {
            final SharedPreferences prefs = ProtonMailApplication.getApplication().getDefaultSharedPreferences();
            if (!prefs.getBoolean(Constants.Prefs.PREF_DONT_SHOW_PLAY_SERVICES, false)) {
                GoogleApiAvailability.getInstance().showErrorNotification(this, e.getConnectionStatusCode());
            }
        } catch (GooglePlayServicesNotAvailableException e) {
            // we already handle this by showing prompt about GCM notifications
        }
    }

    private void initLongRunningTask() {
        // check if storage limit approaching
        final User user = mUserManager.getUser();
        if (user.getMaxSpace() > 0) {
            long percentageUsed = (user.getUsedSpace() * 100) / user.getMaxSpace();
            if (percentageUsed >= Constants.STORAGE_LIMIT_WARNING_PERCENTAGE) {
                mLastStorageLimitEvent = new StorageLimitEvent();
            }
        }

        mIsInitialized = true;
    }

    public boolean isInitialized() {
        return mIsInitialized;
    }

    @NonNull
    public SharedPreferences getDefaultSharedPreferences() {
        return PreferenceManager.getDefaultSharedPreferences(this);
    }

    @NonNull
    public SharedPreferences getSecureSharedPreferences() {
        return SecureSharedPreferences.Companion.getPrefs(ProtonMailApplication.getApplication(), "ProtonMailSSP", Context.MODE_PRIVATE);
    }

    @NonNull
    public SharedPreferences getSecureSharedPreferences(String username) {
        return SecureSharedPreferences.Companion.getPrefsForUser(ProtonMailApplication.getApplication(), username);
    }

    @NonNull
    public Bus getBus() {
        return mBus;
    }

    public JobManager getJobManager() {
        return jobManager;
    }

    public void startJobManager() {
        if (jobManager != null) {
            mNetworkUtil.setCurrentlyHasConnectivity(true);
            jobManager.start();
        }
    }

    @Produce
    public StorageLimitEvent produceStorageLimitEvent() {
        final StorageLimitEvent latestEvent = mLastStorageLimitEvent;
        mLastStorageLimitEvent = null;
        return latestEvent;
    }

    @Produce
    public DraftCreatedEvent produceDraftCreatedEvent() {
        return mLastDraftCreatedEvent;
    }

    @Subscribe
    public void onDraftCreatedEvent(DraftCreatedEvent event) {
        mLastDraftCreatedEvent = event;
    }

    public void resetDraftCreated() {
        mLastDraftCreatedEvent = null;
    }

    @Subscribe
    public void onOrganizationEvent(OrganizationEvent event) {
        if (event.getStatus() == Status.SUCCESS) {
            mOrganization = event.getResponse().getOrganization();
        }
    }

    @Subscribe
    public void onPaymentMethods(GetPaymentMethodsEvent event) {
        if (event.getStatus() == Status.SUCCESS) {
            mPaymentMethods = event.getMethods();
        }
    }

    @Subscribe
    public void onInvalidAccessTokenEvent(InvalidAccessTokenEvent event) {
        final Intent intent = AppUtil.decorInAppIntent(new Intent(this, LoginActivity.class));
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK);
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        Activity activity = mCurrentActivity != null ? mCurrentActivity.get() : null;
        if (activity != null) {
            activity.startActivity(intent);
            activity.finish();
        } else {
            startActivity(intent);
        }
        mUserManager.logoutOffline();
    }

    @Subscribe
    public void onRequestTimeoutEvent(RequestTimeoutEvent event) {
        if (mCurrentActivity != null) {
            Activity activity = mCurrentActivity.get();
            if (activity != null && activity instanceof BaseActivity) {
                ((BaseActivity) activity).showRequestTimeoutSnack();
            }
        }
    }

    @Subscribe
    public void onForceUpgradeEvent(ForceUpgradeEvent event) {
        if (mCurrentActivity != null) {
            final Activity activity = mCurrentActivity.get();
            AlarmReceiver alarmReceiver = new AlarmReceiver();
            alarmReceiver.cancelAlarm(this);
            if (!activity.isFinishing() && (forceUpgradeDialog == null || !forceUpgradeDialog.isShowing())) {
                forceUpgradeDialog = UiUtil.buildForceUpgradeDialog(activity, event.getMessage());
                forceUpgradeDialog.show();
            }
        }
    }

    @Subscribe
    public void onApiOfflineEvent(ApiOfflineEvent event) {
        if (mCurrentActivity != null) {
            final Activity activity = mCurrentActivity.get();
            if (activity != null && !activity.isFinishing()) {
                if (apiOfflineSnackBar == null || !apiOfflineSnackBar.isShown()) {
                    String message = event.getMessage();
                    if (TextUtils.isEmpty(message)) {
                        message = getResources().getString(R.string.api_offline);
                    }
                    final SpannableString s = new SpannableString(message);
                    Linkify.addLinks(s, Linkify.ALL);
                    apiOfflineSnackBar = Snackbar.make(
                            ((ViewGroup) activity.findViewById(android.R.id.content)).getChildAt(0),
                            message, Snackbar
                                    .LENGTH_INDEFINITE);
                    View view = apiOfflineSnackBar.getView();
                    TextView tv = view.findViewById(com.google.android.material.R.id.snackbar_text);
                    tv.setMaxLines(4);
                    tv.setTextColor(getResources().getColor(R.color.icon_purple));
                    apiOfflineSnackBar.setAction(getString(R.string.okay), v -> {
                        if (apiOfflineSnackBar != null) {
                            apiOfflineSnackBar.dismiss();
                        }
                    });
                    apiOfflineSnackBar.setActionTextColor(getResources().getColor(R.color.white));
                    apiOfflineSnackBar.show();
                }
            }
        }
    }

    @Subscribe
    public void onPasswordChangeEvent(PasswordChangeEvent event) {
        if (mCurrentActivity != null) {
            final Activity activity = mCurrentActivity.get();

            switch (event.getStatus()) {
                case SUCCESS: {
                    if (event.getPasswordType() == Constants.PASSWORD_TYPE_LOGIN) {
                        TextExtensions.showToast(activity.getApplicationContext(), R.string.new_login_password_saved);
                    } else if (event.getPasswordType() == Constants.PASSWORD_TYPE_MAILBOX) {
                        TextExtensions.showToast(activity.getApplicationContext(), R.string.new_mailbox_password_saved);
                    }
                }
                break;
                default: {
                    String message = event.getStatusMessage();
                    if (message == null || message.isEmpty()) {
                        message = getString(R.string.default_error_message);
                    }
                    TextExtensions.showToast(activity.getApplicationContext(), message);
                }
                break;
            }
        }
    }

    @Subscribe
    public void onAvailableDomainsEvent(AvailableDomainsEvent event) {
        if (event.getStatus() == Status.SUCCESS) {
            this.mAvailableDomains = event.getDomains();
        }
    }

    @Subscribe
    public void onDownloadAttachmentEvent(DownloadedAttachmentEvent event) {
        final Status status = event.getStatus();
        if (status != Status.FAILED) {
            DownloadUtils.viewAttachment(this, event.getFilename(), !event.isOfflineLoaded());
        }
    }

    private LoginInfoEvent loginInfoEvent;
    private Login2FAEvent login2FAEvent;
    private MailboxLoginEvent mailboxLoginEvent;
    private LoginEvent loginEvent;

    // region login info event
    @Subscribe
    public void onLoginInfoEvent(LoginInfoEvent loginInfoEvent) {
        this.loginInfoEvent = loginInfoEvent;
    }

    @Produce
    public LoginInfoEvent produceLoginInfoEvent() {
        return loginInfoEvent;
    }

    public void resetLoginInfoEvent() {
        loginInfoEvent = null;
    }
    // endregion

    // region login 2fa event
    @Subscribe
    public void onLogin2FAEvent(Login2FAEvent login2FAEvent) {
        this.login2FAEvent = login2FAEvent;
    }

    @Produce
    public Login2FAEvent produceLogin2FAEvent() {
        return login2FAEvent;
    }

    public void resetLogin2FAEvent() {
        login2FAEvent = null;
    }
    // endregion

    // region mailbox event
    @Subscribe
    public void onLoginEvent(MailboxLoginEvent event) {
        mailboxLoginEvent = event;
    }

    @Produce
    public MailboxLoginEvent produceMailboxLoginEvent() {
        return mailboxLoginEvent;
    }

    public void resetMailboxLoginEvent() {
        mailboxLoginEvent = null;
    }
    // endregion

    // region login event
    @Subscribe
    public void onLoginEvent(LoginEvent event) {
        loginEvent = event;
    }

    @Produce
    public LoginEvent produceLoginEvent() {
        return loginEvent;
    }

    public void resetLoginEvent() {
        loginEvent = null;
    }
    // endregion

    public AllCurrencyPlans getAllCurrencyPlans() {
        return mAllCurrencyPlans;
    }

    public void setAllCurrencyPlans(AllCurrencyPlans allCurrencyPlans) {
        this.mAllCurrencyPlans = allCurrencyPlans;
    }

    public boolean hasUpdateOccurred() {
        return mUpdateOccurred;
    }

    public void updateDone() {
        mUpdateOccurred = false;
    }

    @Override
    public AndroidInjector<Activity> activityInjector() {
        return activityInjector;
    }

    private static class RefreshMessagesAndAttachments extends AsyncTask<Void, Void, Void> {

        private final MessagesDatabase messagesDatabase;

        private RefreshMessagesAndAttachments(MessagesDatabase messagesDatabase) {
            this.messagesDatabase = messagesDatabase;
        }

        @Override
        protected Void doInBackground(Void... voids) {
            messagesDatabase.clearAttachmentsCache();
            messagesDatabase.clearMessagesCache();
            return null;
        }

        @Override
        protected void onPostExecute(Void aVoid) {
            MessagesService.Companion.startFetchFirstPage(Constants.MessageLocationType.INBOX, false, null, false);
        }
    }

    private void setupNotificationChannels() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationManager notificationManager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
            INotificationServer notificationServer = new NotificationServer(this, notificationManager);
            notificationServer.createEmailsChannel();
            notificationServer.createAttachmentsChannel();
            notificationServer.createCheckingMailboxNotification();
            notificationServer.createAccountChannel();
        }
    }

    /**
     * {@link MIGRATE_FROM_BUILD_CONFIG_FIELD_DOC}
     */
    private void checkForUpdateAndClearCache() {
        final SharedPreferences prefs = getDefaultSharedPreferences();
        int currentAppVersion = AppUtil.getAppVersionCode(this);
        mNetworkUtil.setCurrentlyHasConnectivity(true);
        //refresh local cache if new app version
        int previousVersion = prefs.getInt(Constants.Prefs.PREF_APP_VERSION, Integer.MIN_VALUE);
        if (previousVersion != currentAppVersion && previousVersion > 0) {
            prefs.edit().putInt(Constants.Prefs.PREF_PREVIOUS_APP_VERSION, previousVersion).apply();
            prefs.edit().putInt(Constants.Prefs.PREF_APP_VERSION, currentAppVersion).apply();
            mUpdateOccurred = true;

            if (mUserManager.isLoggedIn()){
                mUserManager.setLoginState(LOGIN_STATE_TO_INBOX);
            }

            if (BuildConfig.DEBUG) {
                new RefreshMessagesAndAttachments(messagesDatabase).execute();
            }
            if (BuildConfig.FETCH_FULL_CONTACTS && mUserManager.isLoggedIn()) {
                jobManager.addJobInBackground(new FetchContactsEmailsJob(0));
                jobManager.addJobInBackground(new FetchContactsDataJob());
            }
            if (BuildConfig.REREGISTER_FOR_PUSH) {
                GcmUtil.setTokenSent(false);
            }
            jobManager.addJobInBackground(new FetchLabelsJob());
            //new version will get set in RegisterGcmJob
            if (mUserManager != null) {
                // if this version requires the user to be logged out when updatingAttachmentMetadataDatabase
                // and if every single previous version should be force logged out
                // or any specific previous version should be logged out

                // Removed check for updates where we need to logout as it was always false. See doc ref in method header
                if (false) {
                    mUserManager.logoutOffline();
                    AppUtil.deleteDatabases(this, mUserManager.getUsername());
                    AppUtil.deletePrefs();
                }
                if (BuildConfig.DEBUG) {
                    List<String> loggedInUsers = AccountManager.Companion.getInstance(this).getLoggedInUsers();
                    long elapsedTime = SystemClock.elapsedRealtime();
                    for (String userName : loggedInUsers) {
                        User user = mUserManager.getUser(userName);
                        if (!user.isPaidUser()) {
                            user.setShowMobileSignature(true);
                            user.save();
                        }
                        user.setLastInteraction(elapsedTime);
                    }
                }
                if (BuildConfig.DEBUG) {
                    AlarmReceiver alarmReceiver = new AlarmReceiver();
                    alarmReceiver.cancelAlarm(this);
                    startJobManager();
                    mUserManager.removeEmptyUserReferences();
                    TokenManager.Companion.removeEmptyTokenManagers();
                    List<String> loggedInUsers = AccountManager.Companion.getInstance(this).getLoggedInUsers();
                    String currentPrimary = mUserManager.getUsername();
                    jobManager.addJobInBackground(new FetchUserSettingsJob(currentPrimary));
                    for (String loggedInUser : loggedInUsers){
                        if (!loggedInUser.equals(currentPrimary)) {
                            jobManager.addJobInBackground(new FetchUserSettingsJob(loggedInUser));
                        }
                    }
                    eventManager.clearState();
                    alarmReceiver.setAlarm(this);
                }
                TokenManager tokenManager = mUserManager.getTokenManager();
                if (tokenManager != null && TextUtils.isEmpty(tokenManager.getEncPrivateKey())) {
                    User user = mUserManager.getUser();
                    for (Keys key : user.getKeys()) {
                        if (key.isPrimary()) {
                            tokenManager.setEncPrivateKey(key.getPrivateKey()); // it's needed for verification later
                            break;
                        }
                    }
                }
                SharedPreferences secureSharedPreferences = getSecureSharedPreferences(mUserManager.getUsername());
                SharedPreferences defaultSharedPreferences = getDefaultSharedPreferences();
                List<String> loggedInUsers = AccountManager.Companion.getInstance(this).getLoggedInUsers();

                if (defaultSharedPreferences.contains(PREF_SHOW_STORAGE_LIMIT_WARNING)) {
                    secureSharedPreferences.edit().putBoolean(PREF_SHOW_STORAGE_LIMIT_WARNING,
                            defaultSharedPreferences.getBoolean(PREF_SHOW_STORAGE_LIMIT_WARNING, true)).apply();
                    defaultSharedPreferences.edit().remove(PREF_SHOW_STORAGE_LIMIT_WARNING).apply();
                }
                if (defaultSharedPreferences.contains(PREF_SHOW_STORAGE_LIMIT_REACHED)) {
                    secureSharedPreferences.edit().putBoolean(PREF_SHOW_STORAGE_LIMIT_REACHED,
                            defaultSharedPreferences.getBoolean(PREF_SHOW_STORAGE_LIMIT_REACHED, true)).apply();
                    defaultSharedPreferences.edit().remove(PREF_SHOW_STORAGE_LIMIT_REACHED).apply();
                }
                if (defaultSharedPreferences.contains(PREF_LOGIN_STATE)) {
                    for (String user : loggedInUsers) {
                        SharedPreferences secureSharedPreferencesForUser = getSecureSharedPreferences(user);
                        if (mUserManager.getMailboxPassword(user) == null) {
                            mUserManager.logoutAccount(user);
                        } else {
                            secureSharedPreferencesForUser.edit().putInt(PREF_LOGIN_STATE, LOGIN_STATE_TO_INBOX).apply();
                        }
                    }
                    defaultSharedPreferences.edit().remove(PREF_LOGIN_STATE).apply();
                }
                for (String user : loggedInUsers) {
                    SharedPreferences secureSharedPreferencesForUser = getSecureSharedPreferences(user);
                    if (secureSharedPreferencesForUser.contains(PREF_LATEST_EVENT)) {
                        secureSharedPreferencesForUser.edit().remove(PREF_LATEST_EVENT).apply();
                    }
                }
            }
        } else {
            mUpdateOccurred = false;
            if (previousVersion < 0) {
                prefs.edit().putInt(Constants.Prefs.PREF_APP_VERSION, currentAppVersion).apply();
            }
        }
    }

    public UserManager getUserManager() {
        return mUserManager;
    }

    public ProtonMailApiManager getApi() {
        return mApi;
    }

    public ContactsDatabase getContactsDatabase() {
        return contactsDatabase;
    }

    public OpenPGP getOpenPGP() {
        return mOpenPGP;
    }

    public AppComponent getAppComponent() {
        return mAppComponent;
    }

    public EventManager getEventManager() {
        return eventManager;
    }

    public void setCurrentActivity(BaseActivity activity) {
        if (apiOfflineSnackBar != null && apiOfflineSnackBar.isShown()) {
            apiOfflineSnackBar.dismiss();
        }
        apiOfflineSnackBar = null;
        mCurrentActivity = new WeakReference<>(activity);
    }

    public Activity getCurrentActivity() {
        if (mCurrentActivity != null) {
            return mCurrentActivity.get();
        }
        return null;
    }

    public boolean isAppInBackground() {
        return appInBackground;
    }

    public void setAppInBackground(boolean appInBackground) {
        this.appInBackground = appInBackground;
    }

    public List<PaymentMethod> getPaymentMethods() {
        return mPaymentMethods;
    }

    public void clearPaymentMethods() {
        mPaymentMethods = null;
    }

    public Organization getOrganization() {
        return mOrganization;
    }

    public void setOrganization(Organization organization) {
        mOrganization = organization;
    }

    public List<String> getAvailableDomains() {
        return mAvailableDomains == null ? new ArrayList<String>() : mAvailableDomains;
    }

    public void fetchOrganization() {
        GetOrganizationJob getOrganizationJob = new GetOrganizationJob();
        jobManager.addJobInBackground(getOrganizationJob);
    }

    public void notifyLoggedOut(String username) {
        NotificationManager notificationManager = (NotificationManager) getSystemService(
                Context.NOTIFICATION_SERVICE);
        INotificationServer notificationServer = new NotificationServer(this, notificationManager);
        if (mUserManager != null && mUserManager.isLoggedIn()) {
            notificationServer.notifyUserLoggedOut(mUserManager.getUser(username));
        }
    }

    public void notifySingleErrorSendingMessage(Message message, String error, User user) {
        NotificationManager notificationManager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        INotificationServer notificationServer = new NotificationServer(this, notificationManager);
        if (mUserManager != null && mUserManager.isLoggedIn()) {
            notificationServer.notifySingleErrorSendingMessage(message, error, user);
        }
    }

    public void notifyMultipleErrorSendingMessage(List<SendingFailedNotification> sendingFailedNotifications, User user) {
        NotificationManager notificationManager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        INotificationServer notificationServer = new NotificationServer(this, notificationManager);
        if (mUserManager != null && mUserManager.isLoggedIn()) {
            notificationServer.notifyMultipleErrorSendingMessage(sendingFailedNotifications, user);
        }
    }

    public String getCurrentLocale() {
        mCurrentLocale = getResources().getConfiguration().locale.toString();
        return mCurrentLocale;
    }

    public void clearLocaleCache() {
        mCurrentLocale = null;
    }

    public void setChangedSystemTimeDate(boolean changedSystemTimeDate) {
        mChangedSystemTimeDate = changedSystemTimeDate;
        final SharedPreferences pref = ProtonMailApplication.getApplication().getSharedPreferences(Constants.PrefsType.BACKUP_PREFS_NAME, Context.MODE_PRIVATE);
        pref.edit().putBoolean(PREF_TIME_AND_DATE_CHANGED, mChangedSystemTimeDate).apply();
    }

    public boolean isChangedSystemTimeDate() {
        final SharedPreferences pref = ProtonMailApplication.getApplication().getSharedPreferences(Constants.PrefsType.BACKUP_PREFS_NAME, Context.MODE_PRIVATE);
        mChangedSystemTimeDate = pref.getBoolean(PREF_TIME_AND_DATE_CHANGED, false);
        return mChangedSystemTimeDate;
    }

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(CustomLocale.Companion.apply(base));
    }

    @Override
    public void onConfigurationChanged(Configuration newConfig) {
        super.onConfigurationChanged(newConfig);
        CustomLocale.Companion.apply(this);
    }

    public void changeApiProviders(boolean switchToOld, boolean force) {
        final SharedPreferences prefs = ProtonMailApplication.getApplication().getDefaultSharedPreferences();
        networkConfigurator.networkSwitcher.reconfigureProxy(Proxies.Companion.getInstance(null, prefs));
    }
}
