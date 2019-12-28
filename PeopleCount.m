
clear all;
fullname= ['YanArduinoData.txt'];
fid=fopen(fullname,'rt');
fmt=['%s %f %f %d %d'];
SniffedPacket = textscan(fid, fmt, 'Delimiter','|','headerLines', 1,'TreatAsEmpty',{'doHousekeeping():Battery,sendData():Countercleared'}); 
fclose(fid);

MAC=SniffedPacket{1,1};
SequenceNo=SniffedPacket{1,2};
TimeStamp=SniffedPacket{1,3};
Channel=SniffedPacket{1,4};
RSS=SniffedPacket{1,5};
Npackets = length(MAC);
countMac=1;%total num of Unique Mac-adddress
MobileDevice_Total=struct;
MobileDevice_Total(1).mac= MAC{1,1};
MobileDevice_Total(1).rss= RSS(1);
MobileDevice_Total(1).channel= Channel(1);
MobileDevice_Total(1).time= TimeStamp(1);
MobileDevice_Total(1).sequence= SequenceNo(1);

for i=2:Npackets
    if any(strcmp({MobileDevice_Total.mac},MAC{i,1}))
        index=find(strcmp({MobileDevice_Total.mac},MAC{i,1})==1);
        MobileDevice_Total(index).rss= [MobileDevice_Total(index).rss,RSS(i)];
        MobileDevice_Total(index).channel= [MobileDevice_Total(index).channel,Channel(i)];
        MobileDevice_Total(index).time= [MobileDevice_Total(index).time, TimeStamp(i)];
        MobileDevice_Total(index).sequence= [MobileDevice_Total(index).sequence,SequenceNo(i)];
    else
        countMac=countMac+1;
        MobileDevice_Total(countMac).mac=MAC{i,1};
        MobileDevice_Total(countMac).rss= RSS(i);
        MobileDevice_Total(countMac).channel= Channel(i);
        MobileDevice_Total(countMac).time= TimeStamp(i);
        MobileDevice_Total(countMac).sequence= SequenceNo(i);
    end
end

DeviceNo=size(MobileDevice_Total);

% fid_new=fopen('YanArduninoCleanData.txt','wt');
% while ~feof(fid)
%     
%     tline=fgetl(fid);
%     if isempty(tline) 
%         continue;
%     elseif double(tline(1))>=48 && double(tline(1))<=57 %start with number
%         a{1,:}=textscan(tline,'%d %s %d %d %d %d\n','Delimiter',"|");
% %         T = cell2table(a,'VariableNames',{'Subtype','MAC','Sequence','Timestamp','Channel','RSSI'});
% %         writetable(T,'YanArduninoCleanData.dat');
%     for i=1:6
%         fprintf(fid_new,'%d %s %d %d %d %d\n',a{1,1}{i});  
%     end
%         
%         clear a;
%     end
% end
% fclose(fid);
% fclose(fid_new);

