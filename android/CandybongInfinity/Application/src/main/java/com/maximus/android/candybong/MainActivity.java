package com.maximus.android.candybong;

import android.Manifest;
import android.app.Activity;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.util.Log;
import android.view.MenuItem;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.drawerlayout.widget.DrawerLayout;
import androidx.appcompat.app.ActionBarDrawerToggle;
import androidx.fragment.app.Fragment;

import com.google.android.material.navigation.NavigationView;

public class MainActivity extends AppCompatActivity implements NavigationView.OnNavigationItemSelectedListener{


    private DrawerLayout drawerLayout;
    private ActionBarDrawerToggle drawerToggle;
    private NavigationView navigationView;
    private Fragment controlFragment, pairFragment;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        controlFragment = new ControlFragment();
        pairFragment = new PairFragment();

        if (savedInstanceState == null) {
            getSupportFragmentManager().beginTransaction()
                    .setReorderingAllowed(true)
                    .add(R.id.fragment_container_view, controlFragment, null)
                    .commit();
        }


        // drawer layout instance to toggle the menu icon to open
        // drawer and back button to close drawer
        drawerLayout = findViewById(R.id.drawerLayout);
        drawerToggle = new ActionBarDrawerToggle(this, drawerLayout, R.string.open, R.string.close);

        // pass the Open and Close toggle for the drawer layout listener
        // to toggle the button
        drawerLayout.addDrawerListener(drawerToggle);
        drawerToggle.syncState();

        // to make the Navigation drawer icon always appear on the action bar
        getSupportActionBar().setDisplayHomeAsUpEnabled(true);

        // declaring the NavigationView
        navigationView = (NavigationView) findViewById(R.id.navigationView);
        // assigning the listener to the NavigationView
        navigationView.setNavigationItemSelectedListener(this);


        // Use this check to determine whether BLE is supported on the device.  Then you can
        // selectively disable BLE-related features.
        if (!getPackageManager().hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE)) {
            Toast.makeText(this, R.string.ble_not_supported, Toast.LENGTH_LONG).show();
        }

        checkBLEPermission(this, Manifest.permission.ACCESS_FINE_LOCATION);
        //checkBLEPermission(this, Manifest.permission.BLUETOOTH_CONNECT);
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull MenuItem item) {
        if (drawerToggle.onOptionsItemSelected(item)) {
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    public void replaceFragment(@NonNull Fragment fragment) {
        getSupportFragmentManager().beginTransaction()
                .setReorderingAllowed(true)
                .replace(R.id.fragment_container_view, fragment)
                .commit();
    }

    public void showControl() {
        replaceFragment(controlFragment);
    }

    @Override
    public boolean onNavigationItemSelected(@NonNull MenuItem item) {
        switch(item.getItemId()) {
            case R.id.nav_pair:
                Log.d("maximus64", "Pair menu click");
                replaceFragment(pairFragment);
                drawerLayout.closeDrawers();
                return true;
            case R.id.nav_control:
                Log.d("maximus64", "Control menu click");
                replaceFragment(controlFragment);
                drawerLayout.closeDrawers();
                return true;
            case R.id.nav_settings:
                Log.d("maximus64", "Setting menu click");
                return true;
            case R.id.nav_exit:
                // on below line we are finishing activity.
                finish();

                // on below line we are exiting our activity
                System.exit(0);
                return true;
        }
        return false;
    }

    private boolean checkBLEPermission(Activity activity, String perm) {
        if (ActivityCompat.checkSelfPermission(activity,perm) !=
                PackageManager.PERMISSION_GRANTED) {
            // Request the permission directly
            ActivityCompat.requestPermissions(activity,
                    new String[] { Manifest.permission.ACCESS_FINE_LOCATION },
                    Constants.BLE_SCAN_REQUEST_CODE);
            return false;
        }
        return true;
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == Constants.BLE_SCAN_REQUEST_CODE) {
            if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                // Permission is granted, reopen pair fragment
                replaceFragment(pairFragment);
            } else {
                Toast.makeText(this, R.string.ble_permission_requiered, Toast.LENGTH_LONG).show();
            }
        }
    }
}