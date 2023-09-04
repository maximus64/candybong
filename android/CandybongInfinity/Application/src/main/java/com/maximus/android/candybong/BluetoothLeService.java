/*
 * Copyright (C) 2013 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.maximus.android.candybong;

import android.Manifest;
import android.app.Activity;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCallback;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.le.BluetoothLeScanner;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanFilter;
import android.bluetooth.le.ScanSettings;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.util.Log;

import androidx.core.app.ActivityCompat;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Service for managing connection and data communication with a GATT server hosted on a
 * given Bluetooth LE device.
 */
public class BluetoothLeService {

    public class BTNotFoundException extends Exception {}

    public class BTNotEnableException extends Exception {}

    private final static String TAG = "BluetoothLeService";

    private final BluetoothAdapter mBluetoothAdapter;
    private BluetoothDevice mBluetoothDevice;
    private BluetoothGatt mBluetoothGatt;
    private BluetoothLeScanner mBluetoothLeScanner;
    private int mConnectionState = STATE_DISCONNECTED;

    private static final int STATE_DISCONNECTED = 0;
    private static final int STATE_CONNECTING = 1;
    private static final int STATE_CONNECTED = 2;


    private static BluetoothLeService instance;

    private BluetoothLeService() {
        mBluetoothAdapter = BluetoothAdapter.getDefaultAdapter();
    }

    public static BluetoothLeService getInstance() {
        if (instance == null) {
            // Create a new instance if it doesn't exist
            instance = new BluetoothLeService();
        }
        return instance;
    }


    // Implements callback methods for GATT events that the app cares about.  For example,
    // connection change and services discovered.
    private final BluetoothGattCallback mGattCallback = new BluetoothGattCallback() {
        @Override
        public void onConnectionStateChange(BluetoothGatt gatt, int status, int newState) {
            String intentAction;
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                mConnectionState = STATE_CONNECTED;
                Log.i(TAG, "Connected to GATT server.");
                // Attempts to discover services after successful connection.
                Log.i(TAG, "Attempting to start service discovery:" +
                        mBluetoothGatt.discoverServices());

            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                mConnectionState = STATE_DISCONNECTED;
                Log.i(TAG, "Disconnected from GATT server.");
            }
        }

        @Override
        public void onServicesDiscovered(BluetoothGatt gatt, int status) {
            if (status == BluetoothGatt.GATT_SUCCESS) {
                //broadcastUpdate(ACTION_GATT_SERVICES_DISCOVERED);
            } else {
                Log.w(TAG, "onServicesDiscovered received: " + status);
            }
        }

        @Override
        public void onCharacteristicRead(BluetoothGatt gatt,
                                         BluetoothGattCharacteristic characteristic,
                                         int status) {
            if (status == BluetoothGatt.GATT_SUCCESS) {
                //broadcastUpdate(ACTION_DATA_AVAILABLE, characteristic);
            }
        }

        @Override
        public void onCharacteristicChanged(BluetoothGatt gatt,
                                            BluetoothGattCharacteristic characteristic) {
            //broadcastUpdate(ACTION_DATA_AVAILABLE, characteristic);
        }
    };


    private boolean checkBLEPermission(Activity activity, String perm) {
        // Request the permission directly
        //            ActivityCompat.requestPermissions(activity,
        //                    new String[] { perm },
        //                    Constants.BLE_SCAN_REQUEST_CODE);
        return ActivityCompat.checkSelfPermission(activity, perm) == PackageManager.PERMISSION_GRANTED;
    }
    public void startScan(Activity activity, ScanCallback scanCallback) throws BTNotFoundException, BTNotEnableException {
        if (mBluetoothAdapter == null)
            throw new BTNotFoundException();

        if (!mBluetoothAdapter.isEnabled())
            throw new BTNotEnableException();

        if (!checkBLEPermission(activity, Manifest.permission.ACCESS_FINE_LOCATION))
            return;


        // Filter by device name
        List<ScanFilter> scanFilters = new ArrayList<>();
        ScanFilter scanFilter = new ScanFilter.Builder()
                .setDeviceName("TWICE LightStick")
                .build();
        scanFilters.add(scanFilter);

        // Scanning settings
        ScanSettings scanSettings = new ScanSettings.Builder()
                .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                .build();

        mBluetoothLeScanner = mBluetoothAdapter.getBluetoothLeScanner();
        mBluetoothLeScanner.startScan(scanFilters, scanSettings, scanCallback);
    }

    public void stopScan(ScanCallback scanCallback) {
        if (mBluetoothLeScanner != null) {
            mBluetoothLeScanner.stopScan(scanCallback);
            mBluetoothLeScanner = null;
        }
    }

    public void connect(Activity act, BluetoothDevice device) throws BTNotFoundException {
        if (mBluetoothAdapter == null)
            throw new BTNotFoundException();

        // check BLE permission
        checkBLEPermission(act, Manifest.permission.ACCESS_FINE_LOCATION);

        // We want to directly connect to the device, so we are setting the autoConnect
        // parameter to false.
        mBluetoothGatt = device.connectGatt(act, false, mGattCallback);
        Log.d(TAG, "Trying to create a new connection.");
        mBluetoothDevice = device;
        mConnectionState = STATE_CONNECTED;
    }

    public boolean isConnected() {
        return mConnectionState == STATE_CONNECTED;
    }

    /**
     * Disconnects an existing connection or cancel a pending connection. The disconnection result
     * is reported asynchronously through the
     * {@code BluetoothGattCallback#onConnectionStateChange(android.bluetooth.BluetoothGatt, int, int)}
     * callback.
     */
    public void disconnect() {
        if (mBluetoothAdapter == null || mBluetoothGatt == null) {
            Log.w(TAG, "BluetoothAdapter not initialized");
            return;
        }

        mBluetoothGatt.disconnect();
    }

    /**
     * After using a given BLE device, the app must call this method to ensure resources are
     * released properly.
     */
    public void close() {
        if (mBluetoothGatt == null) {
            return;
        }
        mBluetoothGatt.close();
        mBluetoothGatt = null;
    }

    /**
     * Request a read on a given {@code BluetoothGattCharacteristic}. The read result is reported
     * asynchronously through the {@code BluetoothGattCallback#onCharacteristicRead(android.bluetooth.BluetoothGatt, android.bluetooth.BluetoothGattCharacteristic, int)}
     * callback.
     *
     * @param characteristic The characteristic to read from.
     */
    public void readCharacteristic(BluetoothGattCharacteristic characteristic) {
        if (mBluetoothAdapter == null || mBluetoothGatt == null) {
            Log.w(TAG, "BluetoothAdapter not initialized");
            return;
        }
        mBluetoothGatt.readCharacteristic(characteristic);
    }


    public void writeCharacteristic(BluetoothGattCharacteristic characteristic) {
        if (mBluetoothAdapter == null || mBluetoothGatt == null) {
            Log.w(TAG, "BluetoothAdapter not initialized");
            return;
        }
        mBluetoothGatt.writeCharacteristic(characteristic);
    }


    /**
     * Retrieves a list of supported GATT services on the connected device. This should be
     * invoked only after {@code BluetoothGatt#discoverServices()} completes successfully.
     *
     * @return A {@code List} of supported services.
     */
    public List<BluetoothGattService> getSupportedGattServices() {
        if (mBluetoothGatt == null) return null;

        return mBluetoothGatt.getServices();
    }

    public BluetoothGattService getService(UUID uuid) {
        if (mBluetoothGatt == null) return null;

        return mBluetoothGatt.getService(uuid);
    }

    public void sendCommand(final byte[] buf) {
        if (mBluetoothGatt == null) return;

        BluetoothGattService ble_service = mBluetoothGatt.getService(UUID.fromString(SampleGattAttributes.SERVICE_LIGHT_STICK_NORDIC_UUID));
        if (ble_service == null) {
            Log.e(TAG, "cannot find nordic ble service ");
            return;
        }
        BluetoothGattCharacteristic cmd_char = ble_service.getCharacteristic(UUID.fromString(SampleGattAttributes.CHARACTERISTIC_LIGHT_STICK_NORDIC_COMMAND_ENDPOINT_UUID));
        if (cmd_char == null) {
            Log.e(TAG, "cannot find ble command characteristic ");
            return;
        }
        cmd_char.setValue(buf);
        mBluetoothGatt.writeCharacteristic(cmd_char);
    }

    public void doLedOn() {
        final byte[] led_on_cmd = {(byte)0xff, 0x11};
        sendCommand(led_on_cmd);
    }

    public void doLedOff() {
        final byte[] led_off_cmd = {(byte)0xff, 0x12};
        sendCommand(led_off_cmd);
    }

    public void doLedAnimation(int id, int speed) {
        assert(id >= 1 && id <= 9);
        assert(speed >= 0 && speed <= 255);

        final byte[] led_animation = {
                (byte)0xff, 0x14, 0x00, (byte)id, (byte)speed
        };

        sendCommand(led_animation);
    }

    public void doTwiceColorShift(int shift) {
        assert(shift >= 0 && shift <= 255);

        final byte[] twice_color_shift = {
                (byte)0xff, 0x13, 0x00, (byte)shift
        };

        sendCommand(twice_color_shift);
    }


    public void doLedStaticColor(int color, int brightness) {
        int r = Color.red(color);
        int g = Color.green(color);
        int b = Color.blue(color);

        assert(brightness >= 0 && brightness <= 10);

        final byte[] led_static = {
                (byte)0xff, (byte)0xe6, 0x00,
                (byte)r, (byte)g, (byte)b, (byte)brightness
        };

        sendCommand(led_static);
    }

    public void doLedSpinHue(int speed, int hue) {
        assert(speed >= 0 && speed <= 3);

        final byte[] spin_hue_animation = {
                (byte)0xff, (byte)0xe7, (byte)speed, (byte)hue
        };

        sendCommand(spin_hue_animation);
    }


}
