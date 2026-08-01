"""SDK identification from anchored identifiers, never bare vendor substrings."""

from __future__ import annotations

import re
from typing import NamedTuple


class SdkDetection(NamedTuple):
    """`evidence` holds up to three `kind:match` samples that justify the detection."""

    sdk: str
    evidence: tuple[str, ...]


# Anchors must be exact identifiers: bare "segment" matched VP8SetSegmentParams (ISSUE-010).
_SIGNATURES: tuple[tuple[str, str, str], ...] = (
    ("Firebase", "class", r"\bFIR(?:App|Analytics|Auth|Messaging|Firestore|InstanceID)\b"),
    ("Firebase", "bundle-id", r"\bcom\.google\.firebase\b"),
    ("Firebase", "host", r"\b[a-z0-9-]+\.(?:firebaseio\.com|firebaseapp\.com)\b"),
    ("Firebase", "resource", r"\bGoogleService-Info\.plist\b"),
    ("Crashlytics", "class", r"\bFIRCLS[A-Za-z]+\b"),
    ("Crashlytics", "framework", r"(?<![A-Za-z0-9])(?:Firebase)?Crashlytics(?:\.framework)?\b"),
    ("Crashlytics", "bundle-id", r"\bcom\.crashlytics\.data\b"),
    ("AWS Cognito", "class", r"\bAWSCognito[A-Za-z]*\b"),
    ("AWS Cognito", "host", r"\bcognito-(?:idp|identity)\.[a-z0-9-]+\.amazonaws\.com\b"),
    ("AWS S3", "class", r"\bAWSS3(?:TransferUtility|PreSignedURLBuilder|Service)\b"),
    ("AWS S3", "host", r"\b(?:[a-z0-9.-]+\.)?s3[.-][a-z0-9-]*\.?amazonaws\.com\b"),
    ("Auth0", "class", r"\bA0(?:SimpleKeychain|Lock)[A-Za-z]*\b"),
    ("Auth0", "host", r"\b[a-z0-9-]+\.(?:[a-z]{2}\.)?auth0\.com\b"),
    ("Auth0", "package", r"(?<![A-Za-z0-9])Auth0\.(?:swift|framework)\b"),
    ("Auth0", "symbol", r"\bAuth0(?:Authentication|WebAuth|Credentials)\b"),
    ("Clerk", "package", r"(?<![A-Za-z0-9])ClerkKit(?:UI)?\b"),
    ("Clerk", "bundle-id", r"\bcom\.clerk\.[a-z-]+\b"),
    ("Clerk", "host", r"\b[a-z0-9.-]*clerk\.(?:accounts\.dev|clerk\.dev|com)\b"),
    ("Supabase", "class", r"\bSupabaseClient(?:Options)?\b"),
    ("Supabase", "host", r"\b[a-z0-9-]+\.supabase\.(?:co|in)\b"),
    ("Supabase", "package", r"(?<![A-Za-z0-9])supabase-swift\b"),
    ("Mixpanel", "class", r"\bMixpanel(?:People|Instance|Type)\b"),
    ("Mixpanel", "host", r"\bapi(?:-eu)?\.mixpanel\.com\b"),
    ("Mixpanel", "package", r"(?<![A-Za-z0-9])mixpanel-(?:swift|iphone)\b"),
    ("Mixpanel", "bundle-id", r"\bcom\.mixpanel\.[a-z]+\b"),
    ("Amplitude", "class", r"\bAMP(?:TrackingOptions|DatabaseHelper|Identify)\b"),
    ("Amplitude", "host", r"\bapi2?\.amplitude\.com\b"),
    ("Amplitude", "package", r"(?<![A-Za-z0-9])amplitude-(?:swift|ios)\b"),
    ("Amplitude", "bundle-id", r"\bcom\.amplitude\.[a-z]+\b"),
    ("Segment", "class", r"\bSEGAnalytics[A-Za-z]*\b"),
    ("Segment", "host", r"\b(?:api|cdn-settings)\.segment\.(?:io|com)\b"),
    ("Segment", "bundle-id", r"\bcom\.segment\.analytics\b"),
    ("RudderStack", "class", r"\b(?:RSClient|RudderClient|RSMessageBuilder)\b"),
    ("RudderStack", "host", r"\b[a-z0-9-]*\.dataplane\.rudderstack\.com\b"),
    ("RudderStack", "package", r"(?<![A-Za-z0-9])rudder-sdk-(?:ios|swift)\b"),
    ("AppsFlyer", "class", r"\bAppsFlyer(?:Lib|Tracker|Attribution)\b"),
    ("AppsFlyer", "host", r"\b[a-z0-9-]*\.appsflyer\.com\b"),
    ("AppsFlyer", "bundle-id", r"\bcom\.appsflyer\.[a-z-]+\b"),
    ("Adjust", "class", r"\bADJ(?:Config|Event|Attribution)\b"),
    ("Adjust", "host", r"\b(?:app|s2s)\.adjust\.com\b"),
    ("Adjust", "bundle-id", r"\bcom\.adjust\.sdk\b"),
    ("Branch", "class", r"\bB(?:ranchUniversalObject|NCConfig|NCPreferenceHelper)\b"),
    ("Branch", "host", r"\bapi\d?\.branch\.io\b"),
    ("Branch", "bundle-id", r"\bio\.branch\.sdk\b"),
    ("Stripe", "class", r"\bSTP(?:APIClient|PaymentHandler|PaymentIntent|Token)\b"),
    ("Stripe", "host", r"\b(?:api|m|files)\.stripe\.com\b"),
    ("Stripe", "framework", r"(?<![A-Za-z0-9])Stripe(?:Core|Payments|PaymentSheet|ApplePay)\b"),
    ("Braintree", "class", r"\bBT(?:APIClient|Configuration|PaymentMethodNonce)\b"),
    ("Braintree", "host", r"\bapi\.(?:sandbox\.)?braintreegateway\.com\b"),
    ("Braintree", "bundle-id", r"\bcom\.braintreepayments\.[a-z-]+\b"),
    ("Sentry", "class", r"\bSentry(?:Client|SDK|Options|Crash)[A-Za-z]*\b"),
    ("Sentry", "host", r"\b[a-z0-9.-]*\.ingest(?:\.[a-z]{2})?\.sentry\.io\b"),
    ("Sentry", "bundle-id", r"\bio\.sentry\.[a-z-]+\b"),
    ("Datadog", "class", r"\b(?:DatadogCore|DDLogs|DDRUM|DDTrace)\b"),
    ("Datadog", "host", r"\b[a-z0-9.-]*\.datadoghq\.(?:com|eu)\b"),
    ("Datadog", "package", r"(?<![A-Za-z0-9])dd-sdk-ios\b"),
    ("New Relic", "class", r"\bNRMA[A-Za-z]+\b"),
    ("New Relic", "host", r"\bmobile-collector\.newrelic\.com\b"),
    ("New Relic", "framework", r"(?<![A-Za-z0-9])NewRelic\.framework\b"),
    ("Bugsnag", "class", r"\bBugsnag(?:Client|Configuration|Event)\b"),
    ("Bugsnag", "host", r"\b(?:notify|sessions)\.bugsnag\.com\b"),
    ("Bugsnag", "package", r"(?<![A-Za-z0-9])bugsnag-cocoa\b"),
    ("KSCrash", "class", r"\bKSCrash(?:Monitor|Report|Recording)[A-Za-z]*\b"),
    ("KSCrash", "framework", r"(?<![A-Za-z0-9])KSCrash(?:Core|Recording|Filters|ReportingCore)\b"),
    ("Facebook SDK", "framework", r"(?<![A-Za-z0-9])FBSDK(?:CoreKit|LoginKit|ShareKit)\b"),
    ("Facebook SDK", "host", r"\bgraph\.facebook\.com\b"),
    ("Facebook SDK", "bundle-id", r"\bcom\.facebook\.sdk\b"),
    ("Meta Audience Network", "framework", r"(?<![A-Za-z0-9])FBAudienceNetwork\b"),
    ("Meta Audience Network", "class", r"\bFBAd(?:View|Settings|InterstitialAd|NativeAd)\b"),
    ("Google Sign-In", "class", r"\bGID(?:SignIn|GoogleUser|Configuration)\b"),
    ("Google Sign-In", "host", r"\b[a-z0-9-]*\.googleusercontent\.com\b"),
    ("Google Mobile Ads", "class", r"\bGAD(?:MobileAds|Request|BannerView|RewardedAd)[A-Za-z]*\b"),
    ("Google Mobile Ads", "framework", r"(?<![A-Za-z0-9])GoogleMobileAdsResources\b"),
    ("Google Mobile Ads", "bundle-id", r"\bca-app-pub-\d{16}~\d{10}\b"),
    ("Google UMP", "class", r"\bUMP(?:ConsentInformation|ConsentForm|RequestParameters)\b"),
    ("Google UMP", "framework", r"(?<![A-Za-z0-9])UserMessagingPlatformResources\b"),
    ("reCAPTCHA Enterprise", "framework", r"(?<![A-Za-z0-9])RecaptchaEnterprise[A-Za-z]*\b"),
    ("reCAPTCHA Enterprise", "host", r"\brecaptchaenterprise\.googleapis\.com\b"),
    ("AppAuth", "class", r"\bOID(?:AuthState|ServiceConfiguration|AuthorizationRequest)\b"),
    ("AppAuth", "framework", r"(?<![A-Za-z0-9])AppAuthCore\b"),
    ("AppLovin", "class", r"\bALSdk[A-Za-z]*\b|\bMAAdView\b|\bMARewardedAd\b"),
    ("AppLovin", "host", r"\b[a-z0-9-]*\.applovin\.com\b"),
    ("AppLovin", "bundle-id", r"\bcom\.applovin\.[a-z]+\b"),
    ("IronSource", "class", r"\bIS(?:Configurations|Supersonic|BannerView)\b"),
    ("IronSource", "symbol", r"\bIronSource(?:Adapter|Network|Sdk|Ads|Mediation)[A-Za-z]*\b"),
    ("IronSource", "host", r"\b[a-z0-9-]*\.supersonicads\.com\b"),
    ("Unity Ads", "class", r"\bUnityAds(?:Load|Show|Initialization)[A-Za-z]*\b"),
    ("Unity Ads", "framework", r"(?<![A-Za-z0-9])UnityAdsResources\b"),
    ("Unity Ads", "host", r"\b[a-z0-9.-]*\.unityads\.unity3d\.com\b"),
    ("Vungle", "class", r"\bVungle(?:Ads|SDK|Interstitial|Banner)[A-Za-z]*\b"),
    ("Vungle", "framework", r"(?<![A-Za-z0-9])VungleAds\b"),
    ("Vungle", "host", r"\b[a-z0-9-]*\.vungle\.com\b"),
    ("Mintegral", "class", r"\bMTG(?:SDK|Interstitial|Reward|Banner|Native)[A-Za-z]*\b"),
    ("Mintegral", "framework", r"(?<![A-Za-z0-9])MTGSDK[A-Za-z]*\b"),
    ("Mintegral", "host", r"\b[a-z0-9-]*\.rayjump\.com\b"),
    ("Pangle", "class", r"\bBU(?:AdSDKManager|NativeAd|InterstitialAd|RewardedVideoAd)[A-Za-z]*\b"),
    ("Pangle", "host", r"\b[a-z0-9-]*\.pangle(?:le)?\.io\b"),
    ("Chartboost", "class", r"\bCHB(?:Interstitial|Rewarded|Banner|Mediation)[A-Za-z]*\b"),
    ("Chartboost", "host", r"\b[a-z0-9-]*\.chartboost\.com\b"),
    ("OneSignal", "class", r"\bOS(?:Notification|Permission|Subscription)State\b"),
    ("OneSignal", "host", r"\b(?:api|onesignal)\.onesignal\.com\b"),
    ("OneSignal", "framework", r"(?<![A-Za-z0-9])OneSignal(?:Core|Framework)\b"),
    ("Braze", "class", r"\bABK(?:Appboy|InAppMessage|User)[A-Za-z]*\b"),
    ("Braze", "framework", r"(?<![A-Za-z0-9])Braze(?:Kit|UI|Location)\b"),
    ("Braze", "host", r"\bsdk\.[a-z0-9-]*\.braze\.(?:com|eu)\b"),
    ("Intercom", "class", r"\bICM(?:Intercom|Conversation|Message|Attributes)[A-Za-z]*\b"),
    ("Intercom", "host", r"\bapi(?:-iam)?\.intercom\.io\b"),
    ("Intercom", "framework", r"(?<![A-Za-z0-9])Intercom\.framework\b"),
    ("Airship", "class", r"\bUAirship[A-Za-z]*\b|\bUAPush\b"),
    ("Airship", "host", r"\bdevice-api\.(?:asnapieu\.com|urbanairship\.com)\b"),
    ("LaunchDarkly", "class", r"\bLD(?:Client|Config|User|Context)\b"),
    ("LaunchDarkly", "host", r"\b(?:app|events|clientstream)\.launchdarkly\.com\b"),
    ("Algolia", "class", r"\bALG(?:SearchClient|Index)\b"),
    ("Algolia", "host", r"\b[a-z0-9-]+[.-]dsn\.algolia\.net\b"),
    ("Algolia", "package", r"(?<![A-Za-z0-9])algoliasearch-client-swift\b"),
    ("Realm", "class", r"\bRLM(?:Realm|Object|Results)\b"),
    ("Realm", "bundle-id", r"\bio\.realm\.[a-z-]+\b"),
    ("React Native", "class", r"\bRCT(?:Bridge|RootView|EventEmitter|BundleURLProvider)\b"),
    ("React Native", "framework", r"(?<![A-Za-z0-9])React-(?:Core|cxxreact|jsi)\b"),
    ("React Native", "resource", r"\bmain\.jsbundle\b"),
    ("Lottie", "class", r"\b(?:LOTAnimationView|LottieAnimationView)\b"),
    ("Lottie", "framework", r"(?<![A-Za-z0-9])Lottie(?:PrivacyInfo|\.framework)\b"),
    ("Alamofire", "class", r"\bAlamofire\.(?:Session|Request)\b"),
    ("Alamofire", "package", r"(?<![A-Za-z0-9])Alamofire\.framework\b"),
    ("Alamofire", "bundle-id", r"\borg\.alamofire\.[a-z-]+\b"),
    ("PhoneNumberKit", "package", r"(?<![A-Za-z0-9])PhoneNumberKit\b"),
    ("swift-crypto", "package", r"(?<![A-Za-z0-9])swift-crypto(?![a-z-])"),
)

_SWIFT_CHECKOUT_RE = re.compile(r"SourcePackages/checkouts/([A-Za-z0-9_.-]+)")

# Swift bakes `#file` in as "Module/File.swift" but `#filePath` as an absolute build path,
# so a package leaks its identity through whichever literal its own code happens to use.
_SWIFT_FILE_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_]*)/[A-Za-z0-9_+.-]+\.swift$")

_CASE_FREE_KINDS = frozenset({"host", "bundle-id", "package"})

_MAX_EVIDENCE = 3


def _build_scanner() -> tuple[re.Pattern[str], dict[str, tuple[str, str]]]:
    parts = []
    index = {}
    for number, (sdk, kind, pattern) in enumerate(_SIGNATURES):
        group = f"g{number}"
        index[group] = (sdk, kind)
        # Folding case turns a short class prefix like ICM into a symbol-swallowing wildcard.
        body = f"(?i:{pattern})" if kind in _CASE_FREE_KINDS else pattern
        parts.append(f"(?P<{group}>{body})")
    return re.compile("|".join(parts)), index


_SCANNER, _GROUPS = _build_scanner()


def detect_sdks(strings: list[str], resources: list[str] | None = None) -> list[SdkDetection]:
    """Each detection carries the identifiers that produced it, so a reader can judge it."""
    haystack = dict.fromkeys([*strings, *resources] if resources else strings)
    evidence: dict[str, list[str]] = {}
    for line in haystack:
        for match in _SCANNER.finditer(line):
            sdk, kind = _GROUPS[match.lastgroup]
            samples = evidence.setdefault(sdk, [])
            item = f"{kind}:{match.group(0)}"
            if item not in samples and len(samples) < _MAX_EVIDENCE:
                samples.append(item)
    return sorted(SdkDetection(sdk, tuple(items)) for sdk, items in evidence.items())


def detect_swift_modules(strings: list[str]) -> list[str]:
    """Swift module and SPM checkout names recovered from compiled-in source-path literals."""
    names = {m.group(1) for s in strings for m in _SWIFT_CHECKOUT_RE.finditer(s)}
    names |= {m.group(1) for s in strings if (m := _SWIFT_FILE_RE.match(s.strip()))}
    return sorted(names)
