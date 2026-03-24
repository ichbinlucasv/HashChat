package chat.hashchat
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import android.widget.Button
import android.widget.LinearLayout
import android.view.View
import android.app.AlertDialog
import android.content.Intent
class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val layout = LinearLayout(this)
        layout.orientation = LinearLayout.VERTICAL
        val btnNewChat = Button(this)
        btnNewChat.text = "New Chat"
        val btnAddContact = Button(this)
        btnAddContact.text = "Add Contact (link/QR)"
        val btnFiles = Button(this)
        btnFiles.text = "Send File"
        btnFiles.setOnClickListener {
            val intent = Intent(Intent.ACTION_GET_CONTENT)
            intent.type = "*/*"
            startActivityForResult(intent, 1)
        }
        val btnVoice = Button(this)
        btnVoice.text = "Voice Message"
        val btnAudioCall = Button(this)
        btnAudioCall.text = "Audio Call"
        val btnVideoCall = Button(this)
        btnVideoCall.text = "Video Call"
        val btnSettings = Button(this)
        btnSettings.text = "Settings"
        val btnPrivacy = Button(this)
        btnPrivacy.text = "Privacy Settings"
        val btnNetwork = Button(this)
        btnNetwork.text = "Network Settings"
        val btnWipe1 = Button(this)
        btnWipe1.text = "Panic Wipe - Step 1"
        val btnWipe2 = Button(this)
        btnWipe2.text = "Panic Wipe - Step 2 (final)"
        btnWipe2.setOnClickListener {
            AlertDialog.Builder(this)
                .setTitle("Confirm Wipe")
                .setMessage("This will delete ALL data. Click again to proceed.")
                .setPositiveButton("WIPE NOW") { _, _ -> wipeAll() }
                .setNegativeButton("Cancel", null)
                .show()
        }
        layout.addView(btnNewChat)
        layout.addView(btnAddContact)
        layout.addView(btnFiles)
        layout.addView(btnVoice)
        layout.addView(btnAudioCall)
        layout.addView(btnVideoCall)
        layout.addView(btnSettings)
        layout.addView(btnPrivacy)
        layout.addView(btnNetwork)
        layout.addView(btnWipe1)
        layout.addView(btnWipe2)
        setContentView(layout)
    }
    private fun wipeAll() {}
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
    }
}