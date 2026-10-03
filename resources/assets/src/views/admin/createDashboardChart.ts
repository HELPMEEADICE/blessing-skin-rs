import * as echarts from 'echarts/core'
import { SVGRenderer } from 'echarts/renderers'
import { LineChart } from 'echarts/charts'
import {
  DataZoomComponent,
  GridComponent,
  TitleComponent,
  TooltipComponent,
} from 'echarts/components'

echarts.use([
  SVGRenderer,
  LineChart,
  DataZoomComponent,
  GridComponent,
  TitleComponent,
  TooltipComponent,
])

export type SingleChartData = {
  label: string
  xAxis: string[]
  data: number[]
}

export function createDashboardChart(
  element: HTMLDivElement,
  color: string,
  textColor: string,
  data: SingleChartData,
) {
  const chart = echarts.init(element)
  chart.setOption({
    title: {
      text: data.label,
      textStyle: {
        color: textColor,
      },
    },
    textStyle: {
      color: textColor,
    },
    tooltip: {
      trigger: 'axis',
    },
    dataZoom: [
      { type: 'inside', start: 75 },
      { type: 'slider', start: 75 },
    ],
    xAxis: [
      {
        type: 'category',
        boundaryGap: false,
        data: data.xAxis,
      },
    ],
    yAxis: [
      {
        type: 'value',
        minInterval: 1,
        boundaryGap: false,
      },
    ],
    series: [
      {
        name: data.label,
        type: 'line',
        itemStyle: {
          color,
        },
        areaStyle: {
          color,
        },
        data: data.data,
        smooth: true,
      },
    ],
  })
  return chart
}
