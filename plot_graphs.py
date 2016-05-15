from __future__ import division
import plotly.plotly as py
import plotly.graph_objs as go

FROSTWIRE_FILE = 'frostwire.csv'
BITTORRENT_FILE = 'bittorrent_data.csv'
EMULE_FILE = 'emule.csv'
KAT_FILE = 'magnet_data.csv'

data_files = [FROSTWIRE_FILE, BITTORRENT_FILE, EMULE_FILE, KAT_FILE]
protocols = ['Frostwire', 'BitTorrent', 'EMule', 'KickAssTorrents']

file_size_list = [[], [], [], []]
dld_size_list = [[], [], [], []]
extra_dld_perc_list = [[], [], [], []]
num_peers_list = [[], [], [], []]
dld_time_list = [[], [], [], []]
dld_speed_list = [[], [], [], []]

for idx in xrange(4):
    data_file = data_files[idx]
    with open(data_file, 'r') as f:
        next(f)
        for line in f:
            data = line.split(',')
            file_size = int(data[0])
            dld_size = int(data[1])
            extra_dld_perc = (dld_size-file_size)*100/file_size
            num_peers = int(data[2])
            dld_time = float(data[4])
            dld_speed = float(data[3])
            file_size_list[idx].append(file_size)
            dld_size_list[idx].append(dld_size)
            extra_dld_perc_list[idx].append(extra_dld_perc)
            num_peers_list[idx].append(num_peers)
            dld_time_list[idx].append(dld_time)
            dld_speed_list[idx].append(dld_speed)

plot_data = []
colors = ['rgb(0,0,255)', 'rgb(0,255,0)', 'rgb(255,0,0)', 'rgb(0,255,255)']

# #region Extra Download Percentage
# for idx in xrange(4):
#     trace = go.Scatter(
#         x=file_size_list[idx],
#         y=extra_dld_perc_list[idx],
#         name=protocols[idx],
#         mode='markers',
#         marker=dict(
#             #size=num_peers_list[idx],
#             color=colors[idx]
#         )
#     )
#     plot_data.append(trace)
#
# layout = dict(
#     title='Extra Download Percentage',
#     xaxis=dict(
#         title='File size (KB)'
#     ),
#     yaxis=dict(
#         title='Extra Download Percentage'
#     )#
# )
# #endregion

#region Average Download Speed
for idx in xrange(4):
    trace = go.Scatter(
        x=file_size_list[idx],
        y=dld_speed_list[idx],
        name=protocols[idx],
        mode='markers',
        marker=dict(
            size=num_peers_list[idx],
            color=colors[idx]
        )
    )
    plot_data.append(trace)
layout = dict(
    title='Average Download Speed',
    xaxis=dict(
        title='File size (KB)'
    ),
    yaxis=dict(
        title='Avg. Download Speed (Kbps)'
    )
)
#endregion

# #region Average Download Speed
# for idx in xrange(4):
#     trace = go.Scatter(
#         x=file_size_list[idx],
#         y=num_peers_list[idx],
#         name=protocols[idx],
#         mode='markers',
#         marker=dict(
#             color=colors[idx]
#         )
#     )
#     plot_data.append(trace)
# layout = dict(
#     title='Number of Peers',
#     xaxis=dict(
#         title='File size (KB)'
#     ),
#     yaxis=dict(
#         title='Number of Peers'
#     )
# )
#
# #endregion

fig = dict(data=plot_data, layout=layout)

py.plot(fig)

