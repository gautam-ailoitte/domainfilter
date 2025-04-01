package com.example.domainfilter

import android.app.Activity
import android.content.Intent
import android.content.SharedPreferences
import android.net.VpnService
import android.os.Bundle
import android.preference.PreferenceManager
import android.view.Menu
import android.view.MenuItem
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.example.domainfilter.util.FilterManager

class MainActivity : AppCompatActivity() {
    companion object {
        private const val REQUEST_VPN_PERMISSION = 1001
        private const val PREF_VPN_ENABLED = "vpn_enabled"
    }

    private lateinit var btnToggleVpn: Button
    private lateinit var txtStatus: TextView
    private lateinit var txtFilteredCount: TextView
    private lateinit var prefs: SharedPreferences
    private lateinit var filterManager: FilterManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        setSupportActionBar(findViewById(R.id.toolbar))

        btnToggleVpn = findViewById(R.id.btn_toggle_vpn)
        txtStatus = findViewById(R.id.txt_status)
        txtFilteredCount = findViewById(R.id.txt_filtered_count)

        prefs = PreferenceManager.getDefaultSharedPreferences(this)
        filterManager = FilterManager(this)

        // Load initial domain filter lists
        filterManager.loadDefaultFilters()

        btnToggleVpn.setOnClickListener { toggleVpnService() }

        // Start a thread to update statistics periodically
        startStatisticsUpdateThread()
    }

    override fun onResume() {
        super.onResume()
        updateUI()
    }

    private fun updateUI() {
        val isVpnRunning = FilterVpnService.isRunning()

        if (isVpnRunning) {
            btnToggleVpn.setText(R.string.btn_stop_vpn)
            txtStatus.setText(R.string.status_running)
            txtStatus.setTextColor(getColor(R.color.colorActive))
        } else {
            btnToggleVpn.setText(R.string.btn_start_vpn)
            txtStatus.setText(R.string.status_stopped)
            txtStatus.setTextColor(getColor(R.color.colorInactive))
        }

        // Update filtered count
        val filteredCount = FilterVpnService.getFilteredCount()
        txtFilteredCount.text = getString(R.string.stats_filtered_count, filteredCount)
    }

    private fun startStatisticsUpdateThread() {
        Thread {
            while (!isFinishing) {
                runOnUiThread { updateUI() }
                Thread.sleep(1000) // Update every second
            }
        }.apply {
            isDaemon = true
            start()
        }
    }

    private fun toggleVpnService() {
        if (FilterVpnService.isRunning()) {
            stopVpnService()
        } else {
            startVpnService()
        }
    }

    private fun startVpnService() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            // VPN permission not yet granted, request it
            startActivityForResult(intent, REQUEST_VPN_PERMISSION)
        } else {
            // VPN permission already granted
            onVpnPermissionGranted()
        }
    }

    private fun stopVpnService() {
        val intent = Intent(this, FilterVpnService::class.java).apply {
            action = FilterVpnService.ACTION_DISCONNECT
        }
        startService(intent)

        prefs.edit().putBoolean(PREF_VPN_ENABLED, false).apply()
        updateUI()

        Toast.makeText(this, R.string.toast_vpn_stopped, Toast.LENGTH_SHORT).show()
    }

    private fun onVpnPermissionGranted() {
        val intent = Intent(this, FilterVpnService::class.java).apply {
            action = FilterVpnService.ACTION_CONNECT
        }
        startService(intent)

        prefs.edit().putBoolean(PREF_VPN_ENABLED, true).apply()
        updateUI()

        Toast.makeText(this, R.string.toast_vpn_started, Toast.LENGTH_SHORT).show()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)

        if (requestCode == REQUEST_VPN_PERMISSION) {
            if (resultCode == Activity.RESULT_OK) {
                onVpnPermissionGranted()
            } else {
                Toast.makeText(this, R.string.toast_vpn_permission_denied, Toast.LENGTH_LONG).show()
            }
        }
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.menu_main, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.action_settings -> {
                // Launch settings activity (not implemented)
                true
            }
            R.id.action_filter_lists -> {
                // Launch filter lists management (not implemented)
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }
}