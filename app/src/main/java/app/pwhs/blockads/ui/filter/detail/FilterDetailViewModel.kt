package app.pwhs.blockads.ui.filter.detail

import android.app.Application
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import app.pwhs.blockads.R
import app.pwhs.blockads.data.entities.FilterList
import app.pwhs.blockads.data.dao.DnsLogDao
import app.pwhs.blockads.data.dao.FilterListDao
import app.pwhs.blockads.data.repository.CustomFilterManager
import app.pwhs.blockads.data.repository.FilterListRepository
import app.pwhs.blockads.service.AdBlockVpnService
import app.pwhs.blockads.ui.event.UiEvent
import app.pwhs.blockads.ui.event.toast
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

class FilterDetailViewModel(
    private val filterId: Long,
    private val filterListDao: FilterListDao,
    private val dnsLogDao: DnsLogDao,
    private val filterRepo: FilterListRepository,
    private val application: Application,
    private val customFilterManager: CustomFilterManager
) : ViewModel() {

    val filter: StateFlow<FilterList?> = filterListDao.getByIdFlow(filterId)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), null)

    val blockedCount: StateFlow<Int> = dnsLogDao.getBlockedCountByReason(filterId.toString())
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 0)

    private val _testDomainQuery = MutableStateFlow("")
    val testDomainQuery: StateFlow<String> = _testDomainQuery.asStateFlow()

    private val _testDomainResult = MutableStateFlow<Boolean?>(null)
    val testDomainResult: StateFlow<Boolean?> = _testDomainResult.asStateFlow()

    private val _isTestingDomain = MutableStateFlow(false)
    val isTestingDomain: StateFlow<Boolean> = _isTestingDomain.asStateFlow()

    private val _isUpdating = MutableStateFlow(false)
    val isUpdating: StateFlow<Boolean> = _isUpdating.asStateFlow()

    private val _events = MutableSharedFlow<UiEvent>(extraBufferCapacity = 1)
    val events: SharedFlow<UiEvent> = _events.asSharedFlow()

    fun setTestDomainQuery(query: String) {
        _testDomainQuery.value = query
        _testDomainResult.value = null
    }

    fun testDomain() {
        val domain = _testDomainQuery.value.trim()
        if (domain.isBlank()) return
        
        viewModelScope.launch {
            _isTestingDomain.value = true
            _testDomainResult.value = filterRepo.checkDomainInFilter(filterId, domain)
            _isTestingDomain.value = false
        }
    }

    fun toggleFilter() {
        viewModelScope.launch {
            val f = filter.value ?: return@launch
            filterListDao.setEnabled(f.id, !f.isEnabled)
            AdBlockVpnService.requestRestart(application.applicationContext)
        }
    }

    fun updateFilter() {
        viewModelScope.launch {
            val f = filter.value ?: return@launch
            _isUpdating.value = true
            
            // Re-compile custom filters via backend API, else just download built-in files normally
            val result = if (f.isBuiltIn) {
                filterRepo.updateSingleFilter(f)
            } else {
                // CustomFilterManager.updateCustomFilter returns Result<FilterList>
                customFilterManager.updateCustomFilter(f).map { it.ruleCount }
            }
            
            _isUpdating.value = false

            result.fold(
                onSuccess = { count ->
                    _events.toast(R.string.filter_updated, listOf(count))
                    
                    // Reload the filter engine if the binary files were re-downloaded
                    filterRepo.loadAllEnabledFilters()
                },
                onFailure = {
                    _events.toast(R.string.filter_update_failed)
                }
            )
        }
    }

    fun deleteFilter() {
        viewModelScope.launch {
            val f = filter.value ?: return@launch
            if (!f.isBuiltIn) {
                filterListDao.delete(f)
                AdBlockVpnService.requestRestart(application.applicationContext)
            }
        }
    }
}
