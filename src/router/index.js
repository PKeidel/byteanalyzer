import {createRouter, createWebHashHistory} from 'vue-router'
import Dns from '../views/Dns.vue'

const routes = [
    {
        path: '/',
        name: 'Dns',
        component: Dns
    }
]

const router = createRouter({
    history: createWebHashHistory(),
    routes
})

export default router
