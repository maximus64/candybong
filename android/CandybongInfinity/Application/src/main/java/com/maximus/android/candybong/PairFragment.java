package com.maximus.android.candybong;

import android.bluetooth.BluetoothDevice;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanResult;
import android.os.Bundle;

import androidx.appcompat.app.AppCompatActivity;
import androidx.fragment.app.Fragment;

import android.os.Handler;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ProgressBar;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * A simple {@link Fragment} subclass.
 * Use the {@link PairFragment#newInstance} factory method to
 * create an instance of this fragment.
 */
public class PairFragment extends Fragment {

    // TODO: Rename parameter arguments, choose names that match
    // the fragment initialization parameters, e.g. ARG_ITEM_NUMBER
    private static final String ARG_PARAM1 = "param1";
    private static final String ARG_PARAM2 = "param2";
    final Handler handler = new Handler();
    private static final int SCAN_DURATION = 10000; // 10 seconds

    // TODO: Rename and change types of parameters
    private String mParam1;
    private String mParam2;

    private TextView mTextView;
    private Button mPairButton;
    private ProgressBar mProgressBar;

    List<BluetoothDevice> mDeviceList = new ArrayList<BluetoothDevice>();
    Map<String, Integer> devRssiValues = new HashMap<String, Integer>();

    public PairFragment() {
        // Required empty public constructor
    }

    /**
     * Use this factory method to create a new instance of
     * this fragment using the provided parameters.
     *
     * @param param1 Parameter 1.
     * @param param2 Parameter 2.
     * @return A new instance of fragment PairFragment.
     */
    // TODO: Rename and change types and number of parameters
    public static PairFragment newInstance(String param1, String param2) {
        PairFragment fragment = new PairFragment();
        Bundle args = new Bundle();
        args.putString(ARG_PARAM1, param1);
        args.putString(ARG_PARAM2, param2);
        fragment.setArguments(args);
        return fragment;
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (getArguments() != null) {
            mParam1 = getArguments().getString(ARG_PARAM1);
            mParam2 = getArguments().getString(ARG_PARAM2);
        }
    }

    private final ScanCallback scanCallback = new ScanCallback() {
        @Override
        public void onScanResult(int callbackType, ScanResult result) {
            // Process the scan result
            addDevice(result.getDevice(), result.getRssi());
        }

        @Override
        public void onBatchScanResults(List<ScanResult> results) {
            // Process the batch scan results
            for (ScanResult sr : results) {
                addDevice(sr.getDevice(), sr.getRssi());
            }
        }

        @Override
        public void onScanFailed(int errorCode) {
            // Handle scan failure
            mTextView.append(String.format("onScanFailed: errorCode = %d\n", errorCode));
        }
    };
    private void doBLEScan() {

        try {
            BluetoothLeService.getInstance().startScan(getActivity(), scanCallback);
        } catch (BluetoothLeService.BTNotFoundException e) {
            mTextView.append("Bluetooth not found\n");
        } catch (BluetoothLeService.BTNotEnableException e) {
            mTextView.append("Bluetooth not enable\n");
        }
    }

    private void addDevice(BluetoothDevice dev, int rssi) {
        boolean deviceFound = false;

        devRssiValues.put(dev.getAddress(), rssi);

        for (BluetoothDevice listDev : mDeviceList) {
            if (listDev.getAddress().equals(dev.getAddress())) {
                deviceFound = true;
                break;
            }
        }

        if (deviceFound)
            return;

        mTextView.append(String.format("Found Device: %s - %s - %d\n",
                dev.getName(), dev.getAddress(), rssi));
        mDeviceList.add(dev);
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        // Inflate the layout for this fragment
        View view = inflater.inflate(R.layout.fragment_pair,
                container, false);

        mTextView = view.findViewById(R.id.textview);

        mPairButton = view.findViewById(R.id.pair_button);
        mPairButton.setOnClickListener(pairButtonClickListener);
        mProgressBar = view.findViewById(R.id.pair_progressBar);

        ((AppCompatActivity) getActivity()).getSupportActionBar().setTitle(R.string.title_pair);

        return view;
    }

    private BluetoothDevice getHighestRssiDevice() {
        int highest = Integer. MIN_VALUE;
        BluetoothDevice bestDev = null;

        if (mDeviceList.size() == 0)
            return null;

        for (BluetoothDevice dev : mDeviceList) {
            final String addr = dev.getAddress();
            final int rssi = devRssiValues.get(addr);
            if (rssi > highest) {
                highest = rssi;
                bestDev = dev;
            }
        }
        return bestDev;
    }

    private final Runnable mScanningTimeoutRunnable = new Runnable() {
        @Override
        public void run() {
            BluetoothLeService.getInstance().stopScan(scanCallback);

            mProgressBar.setVisibility(ProgressBar.GONE);

            BluetoothDevice dev = getHighestRssiDevice();
            if (dev == null) {
                /* No device found so let user scan again */
                mPairButton.setVisibility(Button.VISIBLE);
                return;
            }

            mTextView.append(String.format("Connecting to: %s - %s\n",
                    dev.getName(), dev.getAddress()));

            try {
                BluetoothLeService.getInstance().connect(getActivity(), dev);
            } catch (BluetoothLeService.BTNotFoundException e) {
                mTextView.append(String.format("Connect Failed %s\n", e));
                return;
            }

            mTextView.append("Connected");

            ((MainActivity) requireActivity()).showControl();
        }
    };

    private final View.OnClickListener pairButtonClickListener = new View.OnClickListener() {
        @Override
        public void onClick(View v) {

            handler.removeCallbacks(mScanningTimeoutRunnable);

            mPairButton.setVisibility(Button.GONE);
            mProgressBar.setVisibility(ProgressBar.VISIBLE);
            mTextView.setText("");
            mTextView.append("\nScanning...\n");
            mDeviceList.clear();
            devRssiValues.clear();
            doBLEScan();

            handler.postDelayed(mScanningTimeoutRunnable, SCAN_DURATION);
        }
    };
}