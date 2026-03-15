package app.pwhs.blockads.ui

import android.annotation.SuppressLint
import androidx.annotation.DrawableRes
import androidx.annotation.StringRes
import androidx.compose.material3.Icon
import androidx.compose.material3.LocalTextStyle
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation3.runtime.NavKey
import androidx.navigation3.runtime.entryProvider
import androidx.navigation3.runtime.rememberNavBackStack
import androidx.navigation3.ui.NavDisplay
import app.pwhs.blockads.R
import app.pwhs.blockads.data.datastore.AppPreferences
import app.pwhs.blockads.ui.about.AboutScreen
import app.pwhs.blockads.ui.appearance.AppearanceScreen
import app.pwhs.blockads.ui.appmanagement.AppManagementScreen
import app.pwhs.blockads.ui.blocklistdomain.BlocklistDomainScreen
import app.pwhs.blockads.ui.customrules.CustomRulesScreen
import app.pwhs.blockads.ui.dnsprovider.DnsProviderScreen
import app.pwhs.blockads.ui.filter.FilterSetupScreen
import app.pwhs.blockads.ui.filter.detail.FilterDetailScreen
import app.pwhs.blockads.ui.firewall.FirewallScreen
import app.pwhs.blockads.ui.home.HomeScreen
import app.pwhs.blockads.ui.logs.LogsScreen
import app.pwhs.blockads.ui.onboarding.OnboardingScreen
import app.pwhs.blockads.ui.profile.ProfileScreen
import app.pwhs.blockads.ui.settings.SettingsScreen
import app.pwhs.blockads.ui.splash.SplashScreen
import app.pwhs.blockads.ui.statistics.StatisticsScreen
import app.pwhs.blockads.ui.whitelist.AppWhitelistScreen
import app.pwhs.blockads.ui.whitelistdomain.WhitelistDomainScreen
import app.pwhs.blockads.ui.wireguard.WireGuardImportScreen
import app.pwhs.blockads.ui.httpsfiltering.HttpsFilteringScreen
import kotlinx.serialization.Serializable
import org.koin.compose.koinInject


@Serializable
data object SplashKey : NavKey

@Serializable
data object OnboardingKey : NavKey

@Serializable
data object HomeAppKey : NavKey

@Composable
fun BlockAdsApp(onRequestVpnPermission: () -> Unit, modifier: Modifier = Modifier) {
    val backStack = rememberNavBackStack(SplashKey)
    NavDisplay(
        backStack = backStack,
        onBack = { if (backStack.size > 1) backStack.removeLastOrNull() },
        modifier = modifier,
        entryProvider = entryProvider {
            entry<SplashKey> {
                SplashScreen(
                    onNavigateToHome = {
                        backStack.removeLastOrNull()
                        backStack.add(HomeAppKey)
                    },
                    onNavigateToOnboarding = {
                        backStack.removeLastOrNull()
                        backStack.add(OnboardingKey)
                    }
                )
            }
            entry<OnboardingKey> {
                OnboardingScreen(
                    onNavigateToHome = {
                        backStack.removeLastOrNull()
                        backStack.add(HomeAppKey)
                    }
                )
            }
            entry<HomeAppKey> {
                HomeApp(
                    onRequestVpnPermission = onRequestVpnPermission
                )
            }

        }
    )
}

@Serializable
data object HomeKey : NavKey

@Serializable
data object FilterKey : NavKey

@Serializable
data object FireWallKey : NavKey

@Serializable
data object DnsProviderKey : NavKey

@Serializable
data object SettingsKey : NavKey

@Serializable
data object StatisticsKey : NavKey

@Serializable
data object LogsKey : NavKey

@Serializable
data object ProfileKey : NavKey

@Serializable
data class FilterDetailKey(val filterId: Long) : NavKey

@Serializable
data object AboutKey : NavKey

@Serializable
data object WhiteListAppKey : NavKey

@Serializable
data object AppManagementKey : NavKey

@Serializable
data object AppearanceKey : NavKey

@Serializable
data object WhiteListDomainKey : NavKey

@Serializable
data object BlockListDomainKey : NavKey


@Serializable
data object CustomRuleKey : NavKey

@Serializable
data object WireGuardImportKey : NavKey

@Serializable
data object HttpsFilteringKey : NavKey

enum class BottomBarScreen(
    @StringRes val labelRes: Int,
    @DrawableRes val icon: Int,
) {
    Home(
        labelRes = R.string.nav_home,
        icon = R.drawable.ic_home
    ),

    FilterSetup(
        labelRes = R.string.nav_filter,
        icon = R.drawable.ic_shield
    ),

    Firewall(
        labelRes = R.string.settings_firewall,
        icon = R.drawable.ic_fire
    ),

    Whitelist(
        labelRes = R.string.dns_provider_title,
        icon = R.drawable.ic_dns
    ),

    Settings(
        labelRes = R.string.nav_settings,
        icon = R.drawable.ic_setting
    )
}

@SuppressLint("UnusedMaterial3ScaffoldPaddingParameter")
@Composable
fun HomeApp(onRequestVpnPermission: () -> Unit = {}) {
    val appPrefs: AppPreferences = koinInject()
    val showBottomNavLabels by appPrefs.showBottomNavLabels.collectAsStateWithLifecycle(
        initialValue = true,
    )
    val homeStack = rememberNavBackStack(HomeKey)
    val filterStack = rememberNavBackStack(FilterKey)
    val firewallStack = rememberNavBackStack(FireWallKey)
    val dnsProviderStack = rememberNavBackStack(DnsProviderKey)
    val settingsStack = rememberNavBackStack(SettingsKey)
    var currentTab by rememberSaveable { mutableStateOf(BottomBarScreen.Home) }

    val currentBackStack = when (currentTab) {
        BottomBarScreen.Home -> homeStack
        BottomBarScreen.FilterSetup -> filterStack
        BottomBarScreen.Firewall -> firewallStack
        BottomBarScreen.Whitelist -> dnsProviderStack
        BottomBarScreen.Settings -> settingsStack
    }

    val bottomBarScreens = listOf(
        BottomBarScreen.Home,
        BottomBarScreen.FilterSetup,
        BottomBarScreen.Firewall,
        BottomBarScreen.Whitelist,
        BottomBarScreen.Settings
    )
    var showBottomBar by rememberSaveable { mutableStateOf(true) }
    Scaffold(
        bottomBar = {
            if (!showBottomBar) return@Scaffold
            NavigationBar(
                containerColor = MaterialTheme.colorScheme.surface,
                contentColor = MaterialTheme.colorScheme.onSurface
            ) {
                bottomBarScreens.forEach { screen ->
                    NavigationBarItem(
                        selected = currentBackStack == when (screen) {
                            BottomBarScreen.Home -> homeStack
                            BottomBarScreen.FilterSetup -> filterStack
                            BottomBarScreen.Firewall -> firewallStack
                            BottomBarScreen.Whitelist -> dnsProviderStack
                            BottomBarScreen.Settings -> settingsStack
                        },
                        onClick = {
                            currentTab = screen
                        },
                        icon = {
                            Icon(
                                painter = painterResource(screen.icon),
                                contentDescription = stringResource(screen.labelRes)
                            )
                        },
                        label = if (showBottomNavLabels) {
                            {
                                Text(
                                    text = stringResource(screen.labelRes),
                                    textAlign = TextAlign.Center,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                    style = LocalTextStyle.current.copy(
                                        fontSize = 12.sp
                                    )
                                )
                            }
                        } else null,
                        alwaysShowLabel = showBottomNavLabels,
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = MaterialTheme.colorScheme.primary,
                            selectedTextColor = MaterialTheme.colorScheme.primary,
                            indicatorColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.12f)
                        )
                    )
                }
            }
        }
    ) {
        NavDisplay(
            backStack = currentBackStack,
            onBack = {
                if (currentBackStack.size > 1) currentBackStack.removeLastOrNull()
                showBottomBar = currentBackStack.size <= 1
            },
            entryProvider = entryProvider {
                entry<HomeKey> {
                    HomeScreen(
                        onRequestVpnPermission = onRequestVpnPermission,
                        onNavigateToLogScreen = {
                            showBottomBar = false
                            homeStack.add(LogsKey)
                        },
                        onNavigateToStatisticsScreen = {
                            showBottomBar = false
                            homeStack.add(StatisticsKey)
                        },
                        onNavigateToProfileScreen = {
                            showBottomBar = false
                            homeStack.add(ProfileKey)
                        }
                    )
                }
                entry<FilterKey> {
                    FilterSetupScreen(
                        onNavigateToFilterDetail = { filterId ->
                            showBottomBar = false
                            filterStack.add(FilterDetailKey(filterId))
                        },
                        onNavigateToCustomRules = {
                            showBottomBar = false
                            filterStack.add(CustomRuleKey)
                        }
                    )
                }
                entry<FireWallKey> {
                    FirewallScreen()
                }
                entry<DnsProviderKey> {
                    DnsProviderScreen()
                }
                entry<SettingsKey> {
                    SettingsScreen(
                        onNavigateToAbout = {
                            showBottomBar = false
                            settingsStack.add(AboutKey)
                        },
                        onNavigateToAppearance = {
                            showBottomBar = false
                            settingsStack.add(AppearanceKey)
                        },
                        onNavigateToAppManagement = {
                            showBottomBar = false
                            settingsStack.add(AppManagementKey)
                        },
                        onNavigateToFilterSetup = {
                            showBottomBar = false
                            currentTab = BottomBarScreen.FilterSetup
                        },
                        onNavigateToBlocklistDomains = {
                            showBottomBar = false
                            settingsStack.add(BlockListDomainKey)
                        },
                        onNavigateToWhitelistDomains = {
                            showBottomBar = false
                            settingsStack.add(WhiteListDomainKey)
                        },
                        onNavigateToWhitelistApps = {
                            showBottomBar = false
                            settingsStack.add(WhiteListAppKey)
                        },
                        onNavigateToWireGuardImport = {
                            showBottomBar = false
                            settingsStack.add(WireGuardImportKey)
                        },
                        onNavigateToHttpsFiltering = {
                            showBottomBar = false
                            settingsStack.add(HttpsFilteringKey)
                        }
                    )
                }
                entry<StatisticsKey> {
                    StatisticsScreen(
                        onNavigateBack = {
                            showBottomBar = true
                            homeStack.removeLastOrNull()
                        }
                    )
                }
                entry<LogsKey> {
                    LogsScreen(
                        onNavigateBack = {
                            showBottomBar = true
                            homeStack.removeLastOrNull()
                        }
                    )
                }
                entry<ProfileKey> {
                    ProfileScreen(
                        onNavigateBack = {
                            showBottomBar = true
                            homeStack.removeLastOrNull()
                        }
                    )
                }
                entry<FilterDetailKey> {
                    FilterDetailScreen(
                        filterId = it.filterId,
                        onNavigateBack = {
                            showBottomBar = true
                            filterStack.removeLastOrNull()
                        }
                    )
                }
                entry<CustomRuleKey> {
                    CustomRulesScreen(
                        onNavigateBack = {
                            showBottomBar = true
                            filterStack.removeLastOrNull()
                        }
                    )
                }
                entry<AboutKey> {
                    AboutScreen(
                        onNavigateBack = {
                            showBottomBar = true
                            settingsStack.removeLastOrNull()
                        }
                    )
                }
                entry<AppearanceKey> {
                    AppearanceScreen(
                        onNavigateBack = {
                            showBottomBar = true
                            settingsStack.removeLastOrNull()
                        }
                    )
                }
                entry<AppManagementKey> {
                    AppManagementScreen(
                        onNavigateBack = {
                            showBottomBar = true
                            settingsStack.removeLastOrNull()
                        }
                    )
                }
                entry<BlockListDomainKey> {
                    BlocklistDomainScreen(
                        onNavigateBack = {
                            showBottomBar = true
                            settingsStack.removeLastOrNull()
                        }
                    )
                }
                entry<WhiteListDomainKey> {
                    WhitelistDomainScreen(
                        onNavigateBack = {
                            showBottomBar = true
                            settingsStack.removeLastOrNull()
                        }
                    )
                }
                entry<WhiteListAppKey> {
                    AppWhitelistScreen(
                        onNavigateBack = {
                            showBottomBar = true
                            settingsStack.removeLastOrNull()
                        }
                    )
                }
                entry<WireGuardImportKey> {
                    WireGuardImportScreen(
                        onNavigateBack = {
                            showBottomBar = true
                            settingsStack.removeLastOrNull()
                        }
                    )
                }
                entry<HttpsFilteringKey> {
                    HttpsFilteringScreen(
                        onNavigateBack = {
                            showBottomBar = true
                            settingsStack.removeLastOrNull()
                        }
                    )
                }
            }
        )
    }
}
