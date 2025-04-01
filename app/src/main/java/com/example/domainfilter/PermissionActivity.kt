package com.example.domainfilter

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class PermissionActivity : AppCompatActivity() {
    companion object {
        private const val REQUEST_VPN_PERMISSION = 1001
    }

    private lateinit var btnGrantPermission: Button
    private lateinit var btnCancel: Button
    private lateinit var txtExplanation: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_permission)

        btnGrantPermission = findViewById(R.id.btn_grant_permission)
        btnCancel = findViewById(R.id.btn_cancel)
        txtExplanation = findViewById(R.id.txt_explanation)

        txtExplanation.setText(R.string.vpn_permission_explanation)

        btnGrantPermission.setOnClickListener { requestVpnPermission() }
        btnCancel.setOnClickListener {
            setResult(Activity.RESULT_CANCELED)
            finish()
        }
    }

    private fun requestVpnPermission() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            // Need to request permission
            startActivityForResult(intent, REQUEST_VPN_PERMISSION)
        } else {
            // Already has permission
            onPermissionGranted()
        }
    }

    private fun onPermissionGranted() {
        setResult(Activity.RESULT_OK)
        finish()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)

        if (requestCode == REQUEST_VPN_PERMISSION) {
            if (resultCode == Activity.RESULT_OK) {
                onPermissionGranted()
            } else {
                setResult(Activity.RESULT_CANCELED)
                finish()
            }
        }
    }
}